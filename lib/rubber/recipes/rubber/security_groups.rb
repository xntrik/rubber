namespace :rubber do

  desc <<-DESC
    Sets up the network security groups
    All defined groups will be created, and any not defined will be removed.
    Likewise, rules within a group will get created, and those not will be removed
  DESC
  required_task :setup_security_groups do
    servers = find_servers_for_task(current_task)

    servers.collect(&:host).each{ |host| cloud.setup_security_groups(host) }
  end

  desc <<-DESC
    Describes the network security groups
  DESC
  required_task :describe_security_groups do
    groups = cloud.describe_security_groups()
    groups.each do |group|
      puts "#{group[:name]}, #{group[:description]}"
      group[:permissions].each do |perm|
        puts "  protocol: #{perm[:protocol]}"
        puts "  from_port: #{perm[:from_port]}"
        puts "  to_port: #{perm[:to_port]}"
        puts "  source_groups: #{perm[:source_groups].collect {|g| g[:name]}.join(", ") }" if perm[:source_groups]
        puts "  source_ips: #{perm[:source_ips].join(", ") }" if perm[:source_ips]
        puts "\n"
      end if group[:permissions]
      puts "\n"
    end
  end

  desc <<-DESC
    Destroy the network security groups
  DESC
  required_task :destroy_security_groups do
    cloud_groups = cloud.describe_security_groups()

    cloud_groups.each do |cloud_group|
      group_name = cloud_group[:name]

      next if group_name !~ /^#{isolate_prefix}/

      begin
        logger.debug "Destroying security group: #{group_name}..."
        cloud.destroy_security_group(group_name)
        logger.debug "Destroyed security group: #{group_name}"
      rescue
        logger.debug "Could not security group: #{group_name}"
      end
    end
  end

  def get_assigned_security_groups(host=nil, roles=[])
    env = rubber_cfg.environment.bind(roles, host)
    security_groups = env.assigned_security_groups

    if env.auto_security_groups
      security_groups << host
      security_groups += roles
    end

    security_groups = security_groups.uniq.compact.reject {|x| x.empty? }
    security_groups = security_groups.collect {|x| isolate_group_name(x) }

    security_groups.each do |group|
      cloud_group = cloud.describe_security_groups(group).first
      security_groups.delete(group) unless cloud_group and cloud_group.has_key?(:permissions) and cloud_group[:permissions].any?
    end if env.purge_empty_security_groups

    return security_groups
  end

  def get_related_security_groups(host=nil, roles=[])
    env = rubber_cfg.environment.bind(roles, host)
    security_group_defns = Hash[env.security_groups.to_a]
    sghosts = (rubber_instances.collect{|ic| ic.name } + [host]).uniq.compact
    sgroles = (rubber_instances.all_roles + roles).uniq.compact
    inject_auto_security_groups(security_group_defns, sghosts, sgroles)
  end

  def setup_security_groups(host=nil, roles=[], vpc_id=nil)
    if rubber_cfg.environment.bind(roles, host).auto_security_groups
      security_group_defns = get_related_security_groups(host, roles)
      sync_security_groups(security_group_defns, vpc_id, host)
    else
      security_group_defns = Hash[rubber_cfg.environment.bind(roles, host).security_groups.to_a]
      sync_security_groups(security_group_defns, vpc_id, host)
    end
  end

  def inject_auto_security_groups(groups, hosts, roles)
    hosts.each do |name|
      group_name = name
      groups[group_name] ||= {'description' => "Rubber automatic security group for host: #{name}", 'rules' => []}
    end
    roles.each do |name|
      group_name = name
      groups[group_name] ||= {'description' => "Rubber automatic security group for role: #{name}", 'rules' => []}
    end
    return groups
  end

  def isolate_prefix
    return "#{rubber_env.app_name}_#{Rubber.env}_"
  end

  def isolate_group_name(group_name)
    if rubber_env.isolate_security_groups
      group_name =~ /^#{isolate_prefix}/ ? group_name : "#{isolate_prefix}#{group_name}"
    else
      group_name
    end
  end

  def isolate_groups(groups)
    renamed = {}
    groups.each do |name, group|
      new_name = isolate_group_name(name)
      new_group =  Marshal.load(Marshal.dump(group))
      new_group['rules'].each do |rule|
        old_ref_name = rule['source_group_name']
        if old_ref_name
          # don't mangle names if the user specifies this is an external group they are giving access to.
          # remove the external_group key to allow this to match with groups retrieved from cloud
          is_external = rule.delete('external_group')
          if ! is_external && old_ref_name !~ /^#{isolate_prefix}/
            rule['source_group_name'] = isolate_group_name(old_ref_name)
          end
        end
      end
      renamed[new_name] = new_group
    end
    return renamed
  end

  def sync_security_groups(groups, vpc_id=nil, host)
    return unless groups

    groups = Rubber::Util::stringify(groups)
    groups = isolate_groups(groups)
    group_keys = groups.keys.clone()

    # For each group that does already exist in cloud
    cloud_groups = cloud.describe_security_groups()
    cloud_groups.each do |cloud_group|
      group_name = cloud_group[:name]

      # skip those groups that don't belong to this project/env
      next if rubber_env.isolate_security_groups && group_name !~ /^#{isolate_prefix}/

      if group_keys.delete(group_name)
        # sync rules
        logger.debug "Security Group already in cloud, syncing rules: #{group_name} #{'(vpc: ' + vpc_id + ')' if vpc_id}"
        group = groups[group_name]

        # convert the special case default rule into what it actually looks like when
        # we query ec2 so that we can match things up when syncing
        rules = group['rules'].clone
        group['rules'].each do |rule|
          if [2, 3].include?(rule.size) && rule['source_group_name'] && rule['source_group_account']
            rules << rule.merge({'protocol' => 'tcp', 'from_port' => '1', 'to_port' => '65535' })
            rules << rule.merge({'protocol' => 'udp', 'from_port' => '1', 'to_port' => '65535' })
            rules << rule.merge({'protocol' => 'icmp', 'from_port' => '-1', 'to_port' => '-1' })
            rules.delete(rule)
          end
        end

        rule_maps = []

        # first collect the rule maps from the request (group/user pairs are duplicated for tcp/udp/icmp,
        # so we need to do this up front and remove duplicates before checking against the local rubber rules)
        cloud_group[:permissions].each do |rule|
          source_groups = rule.delete(:source_groups)
          if source_groups
            source_groups.each do |source_group|
              rule_map = rule.clone
              rule_map.delete(:source_ips)
              rule_map[:source_group_name] = source_group[:name]
              rule_map[:source_group_account] = source_group[:account]
              rule_map = Rubber::Util::stringify(rule_map)
              rule_maps << rule_map unless rule_maps.include?(rule_map)
            end
          else
            rule_map = Rubber::Util::stringify(rule)
            rule_maps << rule_map unless rule_maps.include?(rule_map)
          end
        end if cloud_group[:permissions]
        # For each rule, if it exists, do nothing, otherwise remove it as its no longer defined locally
        rule_maps.each do |rule_map|
          if rules.delete(rule_map)
            # rules match, don't need to do anything
            # logger.debug "Rule in sync: #{rule_map.inspect}"
          else
            # rules don't match, remove them from cloud and re-add below
            answer = nil
            msg = "Rule '#{rule_map.inspect}' exists in cloud, but not locally"
            if rubber_env.prompt_for_security_group_sync
              answer = Capistrano::CLI.ui.ask("#{msg}, remove from cloud? [y/N]: ")
            else
              logger.info(msg)
            end

            if answer =~ /^y/
              rule_map = Rubber::Util::symbolize_keys(rule_map)
              if rule_map[:source_group_name]
                cloud.remove_security_group_rule(group_name, rule_map[:protocol], rule_map[:from_port], rule_map[:to_port], {:name => rule_map[:source_group_name], :account => rule_map[:source_group_account]})
              else
                rule_map[:source_ips].each do |source_ip|
                  cloud.remove_security_group_rule(group_name, rule_map[:protocol], rule_map[:from_port], rule_map[:to_port], source_ip)
                end if rule_map[:source_ips]
              end
            end
          end
        end

        rules.each do |rule_map|
          # create non-existing rules
          logger.debug "Missing rule, creating: #{rule_map.inspect}"
          rule_map = Rubber::Util::symbolize_keys(rule_map)
          if rule_map[:source_group_name]
            cloud.add_security_group_rule(group_name, rule_map[:protocol], rule_map[:from_port], rule_map[:to_port], {:name => rule_map[:source_group_name], :account => rule_map[:source_group_account]})
          else
            rule_map[:source_ips].each do |source_ip|
              cloud.add_security_group_rule(group_name, rule_map[:protocol], rule_map[:from_port], rule_map[:to_port], source_ip)
            end if rule_map[:source_ips]
          end
        end
      else
        # delete group
        answer = nil
        msg = "Security group '#{group_name}' exists in cloud but not locally"
        if rubber_env.prompt_for_security_group_sync
          answer = Capistrano::CLI.ui.ask("#{msg}, remove from cloud? [y/N]: ")
        else
          logger.debug(msg)
        end
        cloud.destroy_security_group(group_name) if answer =~ /^y/
      end
    end

    # For each group that didnt already exist in cloud
    group_keys.each do |group_name|
      group = groups[group_name]
      logger.debug "Creating new security group: #{group_name} #{'(vpc: ' + vpc_id + ')' if vpc_id}"
      # create each group
      cloud.create_security_group(group_name, group['description'], vpc_id)
      # create rules for group
      group['rules'].each do |rule_map|
        logger.debug "Creating new rule: #{rule_map.inspect}"
        rule_map = Rubber::Util::symbolize_keys(rule_map)
        if rule_map[:source_group_name]
          cloud.add_security_group_rule(group_name, rule_map[:protocol], rule_map[:from_port], rule_map[:to_port], {:name => rule_map[:source_group_name], :account => rule_map[:source_group_account]})
        else
          rule_map[:source_ips].each do |source_ip|
            cloud.add_security_group_rule(group_name, rule_map[:protocol], rule_map[:from_port], rule_map[:to_port], source_ip)
          end if rule_map[:source_ips]
        end
      end
    end
  end

end
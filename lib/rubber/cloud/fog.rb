require 'fog'
require 'rubber/cloud/fog_storage'

module Rubber
  module Cloud

    class Fog < Base

      attr_reader :compute_provider, :storage_provider

      def initialize(env, capistrano)
        super(env, capistrano)

        compute_credentials = Rubber::Util.symbolize_keys(env.compute_credentials) if env.compute_credentials
        storage_credentials = Rubber::Util.symbolize_keys(env.storage_credentials) if env.storage_credentials

        @compute_provider = compute_credentials ? ::Fog::Compute.new(compute_credentials) : nil
        @storage_provider = storage_credentials ? ::Fog::Storage.new(storage_credentials) : nil
      end

      def storage(bucket)
        return Rubber::Cloud::FogStorage.new(@storage_provider, bucket)
      end

      def table_store(table_key)
        raise NotImplementedError, "No table store available for generic fog adapter"
      end

      # convert the security group names to IDs
      def convert_security_groups_to_ids(security_groups)
        security_group_ids = security_groups.map do |group_name|
          group = @compute_provider.security_groups.get(group_name)
          group.group_id if group
        end
        security_group_ids.compact
      end

      def create_instance(options={})
        sg_ids = convert_security_groups_to_ids(options[:security_groups])
        puts "\tConvert security group names #{options[:security_groups]} to ids #{sg_ids}"
        response = @compute_provider.servers.create(:image_id => options[:ami],
                                                    :flavor_id => options[:ami_type],
                                                    :security_group_ids => sg_ids,
                                                    :availability_zone => options[:availability_zone],
                                                    :key_name => env.key_name,
                                                    :vpc_id => options[:vpc_id],
                                                    :subnet_id => options[:subnet_id],
                                                    :tenancy => options[:tenancy])
        instance_id = response.id
        return instance_id
      end

      def destroy_instance(instance_id)
        response = @compute_provider.servers.get(instance_id).destroy()
      end

      def destroy_spot_instance_request(request_id)
        @compute_provider.spot_requests.get(request_id).destroy
      end

      def reboot_instance(instance_id)
        response = @compute_provider.servers.get(instance_id).reboot()
      end

      def stop_instance(instance, force=false)
        # Don't force the stop process. I.e., allow the instance to flush its file system operations.
        response = @compute_provider.servers.get(instance.instance_id).stop(force)
      end

      def start_instance(instance)
        response = @compute_provider.servers.get(instance.instance_id).start()
      end

      def create_static_ip(within_vpc)
        opts = {}
        opts[:domain] = 'vpc' if within_vpc
        address = @compute_provider.addresses.create(opts)
        return address.public_ip
      end

      def attach_static_ip(ip, instance_id)
        address = @compute_provider.addresses.get(ip)
        server = @compute_provider.servers.get(instance_id)
        response = (address.server = server)
        return !response.nil?
      end

      def detach_static_ip(ip)
        address = @compute_provider.addresses.get(ip)
        response = (address.server = nil)
        return !response.nil?
      end

      def describe_static_ips(ip=nil)
        ips = []
        opts = {}
        opts["public-ip"] = ip if ip
        response = @compute_provider.addresses.all(opts)
        response.each do |item|
          ip = {}
          ip[:instance_id] = item.server_id
          ip[:ip] = item.public_ip
          ips << ip
        end
        return ips
      end

      def destroy_static_ip(ip)
        address = @compute_provider.addresses.get(ip)
        return address.destroy
      end

      def create_image(image_name)
        raise NotImplementedError, "create_image not implemented in generic fog adapter"
      end

      def describe_images(image_id=nil)
        images = []
        opts = {"Owner" => "self"}
        opts["image-id"] = image_id if image_id
        response = @compute_provider.images.all(opts)
        response.each do |item|
          image = {}
          image[:id] = item.id
          image[:location] = item.location
          image[:root_device_type] = item.root_device_type
          images << image
        end
        return images
      end

      def destroy_image(image_id)
        raise NotImplementedError, "destroy_image not implemented in generic fog adapter"
      end

      def describe_load_balancers(name=nil)
        raise NotImplementedError, "describe_load_balancers not implemented in generic fog adapter"
      end

      # resource_id is any Amazon resource ID (e.g., instance ID or volume ID)
      # tags is a hash of tag_name => tag_value pairs
      def create_tags(resource_id, tags)
        # Tags need to be created individually in fog
        tags.each do |k, v|
          @compute_provider.tags.create(:resource_id => resource_id,
                                        :key => k.to_s, :value => v.to_s)
        end
      end
    end
  end
end

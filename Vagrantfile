# -*- mode: ruby -*-
# vi: set ft=ruby :

VAGRANTFILE_API_VERSION = '2'

$DEFAULTS = {
  :cpus => 1,
  :mem => 1024,
}

# Required plugins. If you encounter errors relating to fog, try manually
# installing fog-libvirt
required_plugins = %w[vagrant-env vagrant-libvirt vagrant-reload]

return if !Vagrant.plugins_enabled?
plugins_to_install = required_plugins.select { |plugin|
  !Vagrant.has_plugin?(plugin)
}

if plugins_to_install.any?
  system("vagrant plugin install #{plugins_to_install.join(' ')}",
         :chdir=>"/tmp")
  exit
end

# Guest config
ENV["LC_ALL"] = "en_US.UTF-8"
ENV['VAGRANT_DEFAULT_PROVIDER'] = "libvirt"
ENV["BOX_NAME"] = "fedora/36-cloud-base"

Vagrant.configure("2") do |config|
  config.env.enable

  # Box
  config.vm.box = ENV["BOX_NAME"]

  # Hostname
  hostname = "kmod-sel4vm-devel-#{ENV["BOX_NAME"].rpartition("/")[-1]}"

  config.vm.hostname = hostname

  # disable default sync
  config.vm.synced_folder '.', '/vagrant', disabled: true

  # Sync code to guest
  # Firewall must allow ports:
  # nfs		2049                       ALLOW       <ip>/24
  config.vm.synced_folder "./", "/home/vagrant/sel4",
    type: "nfs",
    nfs_version: 4,
    nfs_udp: false

  config.vm.network "private_network", type: "dhcp"

  config.vm.define hostname do |machine_name|
    machine_name.vm.provider "libvirt" do |lv, override|
      lv.cpus          = $DEFAULTS[:cpus]
      lv.memory        = $DEFAULTS[:mem]
      lv.driver        = "kvm"
      lv.nested        = true
      lv.disk_bus      = "virtio"
      lv.disk_driver[:cache]  = 'directsync'

      lv.nic_model_type = 'virtio'
      lv.management_network_name = 'kmod-sel4vm-devel'
      lv.management_network_address = '192.168.146.0/24'
      lv.management_network_guest_ipv6 = false

      # Workaround for private network error
      lv.qemu_use_session = false
    end
  end

  # Provision devel tools
  $script = <<-SCRIPT
sudo dnf upgrade -y
sudo dnf install kernel-devel -y
SCRIPT

  config.vm.provision "shell", inline: $script

  config.vm.provision :reload
end

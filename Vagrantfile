# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure('2') do |config|
  config.vm.box = 'ubuntu/trusty64'
  config.vm.box_version = '=14.04'
  config.vm.box_check_update = true

  config.ssh.forward_agent = true

  config.vm.provider :virtualbox do |vb|
    vb.customize [
      'modifyvm', :id,
      '--memory', '2048',
      '--natdnshostresolver1', 'off',
      '--natdnsproxy1', 'on',
      '--accelerate3d', 'off',
    ]
  end

  config.vm.define :master do |machine|
    machine.vm.hostname = 'dev'

    machine.vm.provider :virtualbox do |vb|
      vb.customize [
        'modifyvm', :id,
        '--name', 'Zabbix Template for Varnish Cache',
      ]
    end

    machine.vm.provision :salt do |salt|
      salt.pillar({
        'mysql.root' => {
          'password' => 's3cr3t',
        },
        'mysql.zabbix' => {
          'name' => 'zabbix',
          'user' => 'zabbix',
          'password' => 'zabbix',
        },
      })
      salt.minion_config = 'extras/envs/dev/salt/minion'
      salt.run_highstate = true
      salt.verbose = true
      salt.log_level = 'info'
      salt.colorize = true
      salt.install_type = 'git'
      salt.install_args = 'v2015.2'
    end

    machine.vm.network :public_network
    machine.vm.network :private_network, ip: '192.168.100.172'

    machine.vm.synced_folder '.', '/vagrant', :nfs => false
    machine.vm.synced_folder 'extras/envs/dev/salt/roots', '/srv', :nfs => false
  end
end

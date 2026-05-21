# -*- mode: ruby -*-

Vagrant.configure("2") do |config|
  config.vm.box = "ubuntu/jammy64"
  config.vm.hostname = "helpforge"

  config.vm.network "private_network", ip: "192.168.56.102"
  config.vm.network "forwarded_port", guest: 80, host: 8082, host_ip: "127.0.0.1"

  config.vm.provider "virtualbox" do |vb|
    vb.name = "HelpForge-CTF"
    vb.memory = "2048"
    vb.cpus = 2
    vb.gui = false
  end

  config.vm.provision "ansible_local" do |ansible|
    ansible.playbook = "ansible/playbook.yml"
    ansible.install = true
    ansible.install_mode = "pip"
    ansible.version = "9.5.1"
    ansible.verbose = "v"
    ansible.extra_vars = {
      helpforge_ip: "192.168.56.102",
      mysql_root_password: "80ffabd9008a3ff9f016e7c7325c2280",
      glpi_db_name: "glpidb",
      glpi_db_user: "glpiuser",
      glpi_db_password: "HelpForge_DB_Backend_2024!",
      glpi_checksum: "",
      techops_name: "techops",
      techops_password: "TechOps_HelpForge24",
      user_flag: "FLAG{917b43b3f6ec820a25ed2cb465426259}",
      root_flag: "FLAG{d5a31615c10bb7671aa2f4bbbd161f05}",
      disable_ipv6: false
    }
  end

  config.vm.post_up_message = <<-MSG
HelpForge CTF ready.
HTTP: http://192.168.56.102/ or http://127.0.0.1:8082/
FTP:  ftp://192.168.56.102/
SSH:  ssh techops@192.168.56.102 after cracking the intended password

Run verification:
  ./verify.sh

Run final cleanup before export:
  ./cleanup.sh
MSG
end

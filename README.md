# Multiboot Arch Linux / Windows with Secure Boot (as of 12/02/2023)

Guide mostly written by @ShinySaana.
Steps mostly figured out by @LunarLambda.

> Note: This guide was written by ~~nerds~~ enthusiasts who wanted a reasonably secure system for their own use case. Follow this guide at your own risks, obviously neither warranty nor support is provided. It mostly worked on two of our machines, so this is obviously not extensive. This guide also assumes some knowledge about Arch Linux installation, booting from ISOs, and so on.

> Note: Can be adapted for Manjaro (this has been done). See https://forum.manjaro.org/t/root-tip-how-to-do-a-manual-manjaro-installation/12507 for more informations. You'd probably need to adapt the steps described depending on your needs. This is outside the scope of this guide, however.
## Terraform your disk

- Start from clean drive (or format it during the fdisk step)
- Boot from a standard ArchISO drive
- Connect to the internet (ethernet is prefered; wifi should be doable if drivers are available in the ArchISO image,see https://wiki.archlinux.org/title/Network_configuration/Wireless)
	- You shoud be able to directly refer to the Arch Linux Installation Guide from this computer if needed
	- Or this guide, too :)

- Partition target disk(s) in GPT with fdisk
	- Target example (this can be obviously adapted to cover multiple disks following your own configuration, needs, and use cases):
	```
	- 1GB UEFI (at least)
	- 1TB Linux (which will be split via LVM later)
		- 200 System
		- 800 Data
	- 200 GB Windows System
	- 800 GB Windows Data 
	```
	 > Tip: fdisk will accept `GB` as the unit if you got ripped off from the manufacturer with false units marketing (you 100% got ripped off, why is this even a thing)
	- Don't forget to set the partitions type with the `t` command (1 for UEFI, 11 for Windows, 20 for Linux).

- Encrypt the Linux partition with a password
	- `cryptsetup luksFormat /dev/<Linux Partition>`
	- `cryptsetup open /dev/<Linux Partition> <deviceNameLinux>`
	- sanity check: `lsblk -f` should report this disk

- OPTIONAL: LVM the Linux encrypted partiton
	- `pvcreate /dev/mapper/<deviceNameLinux>`
	- `vgcreate <lvmLinuxName> /dev/mapper/<deviceNameLinux>`
	- (Following earlier example) 
		- `lvcreate -L200GB -n root <lvmLinuxName>`
		- `lvcreate -l100%FREE -n home <lvmLinuxName>`

- Format your partitions:
	- UEFI:
		- `mkfs.fat -F32 /dev/<UEFI partition>`
	- Linux: (Following earlier example)
		- `mkfs.ext4 /dev/<lvmLinuxName>/root`
		- `mkfs.ext4 /dev/<lvmLinuxName>/home`
	- Windows:
		> Windows installer needs its boot partition to be NTFS **even before** it even tries to read it, *even if only to format it directly afterwards*. **Yeah**.
		- `pacman -S ntfs-3g`
		- `mkfs.ntfs /dev/<Windows Partition>`

- Mount your partitions:
	- Root first:
		- `mount /dev/<lvmLinuxName>/root /mnt`
	- UEFI second:
		- `mkdir /mnt/efi`
		- `mount /dev/<UEFI partition> /mnt/efi`
	- OPTIONAL: home third
		- `mkdir /mnt/home`
		- `mount /dev/<lvmLinuxName>/home /mnt/home`
	- `lsblk` check!


## Install Arch Linux

- pacman mirror list should be auto generated when connected to the network; you can ensure this with `cat /etc/pacman.d/mirrorlist`; if not, trouble shoot that. We had no issue with it, so if it's not there, good luck?
- `pacstrap -K /mnt base linux linux-firmware` for essential packages
- `pacman -S extra/arch-install-scripts`
- `genstab -U /mnt >> /mnt/etc/fstab` 
- `arch-chroot /mnt`
	- install your packages, at least a text editor (not included by default now!) and lvm2 if you used LVM earlier. Example:
		- `neovim zsh sudo networkmanager lvm2 (intel/amd)-ucode git`
	 - `ln -sf /ush/share/zoneinfo/<region>/<city> /etc/localtime`
	 - `hwclock --systohc --utc`
		> Yes, Windows will fuck it up. Fix it in Windows later rather than in Linux, it's Windows who's wrong :c
	- setup your locales
		- `vim /etc/locale.gen`
		- `locale-gen`
		- `vim /etc/locale.conf`
		- `vim /etc/vconsole.conf` for the virtual console setup
	- `vim /etc/hostname` and set your hostname
	- initramfs time! `mkinitcpio -P`
	- `passwd` for root password
	- Boot loader time!
		> Note: GRUB can be... janky, with this setup, and maybe too feature bloated for the "I would like a menu to choose which OS to boot please" use case. This guide will therefore use systemd-boot because it's a much more simple, "straight to the point" bootloader, supporting LUKS2 encryption, perfect for our use case.
		- `vim /etc/mkinitcpio.conf`
			- `HOOKS=(base systemd autodetect modconf kms keyboard sd-vconsole block sd-encrypt lvm2 filesystems fsck)`, in this order.
		- `vim /etc/kernel/cmdline`
			- `loglevel=3 rw root=/dev/<lvmLinuxName>/root rd.luks.name=<UUID of Linux Partition >=<deviceNameLinux>`
		- Setup a unified kernel image (UKIs are weird but also quite nice) (conveniently easy to sign for Secure Boot later)
			- `vim /etc/mkinitcpio.d/linux.preset`
				- add `ALL_microcode=(/boot/*-ucode.img)`
				- add `default_uki="/efi/EFI/Linux/arch.efi"`
			- `mkdir /efi/EFI/Linux`
			- `mkinitcpio -p <deviceNameLinux>`
		`bootctl install`
`reboot` !

## Post install your Arch partition

- Sanity test: `lsblk`
- `EDITOR=nvim visudo`
	- uncomment the wheel group line
- `useradd -mG wheel -s /bin/zsh <user>`
- `passwd <user>`
- login as `<user>`
- sanity check: `sudo -i`
- `passwd -l root`
- If on wifi:
	- `sudo systemctl enable --now NetworkManager`
	- `sudo nmtui` 

- Anything else you might need at this point; dotfiles, gui; etc. We would recommend to set this up only after Secure Boot is done being configured.

## Install Windows

- Download the Windows ISO of your choice. WoeUSB is recommended to flash it onto a USB drive. We won't expend on how to create it here.
- After booting into the Windows ISO, choose Custom Install, then choose your prefered Windows partiton.
- It's fine if you don't have a product key. Promise :)
- Post-install, in the OOBE, if you're installing W11 and you want a local account rather than a Microsoft account (Pro edition only):
	- Shift + F10
	- run `OOBE\BYPASSNRO`. Will reboot.
- massgrave.dev :)
- Usual "windows update / manually check for update / install them / reboot / windows update / reboot" loop on a fresh Windows install. 
- Time to fix the time!
	- Open an admin CMD
	- `reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\TimeZoneInformation" /v RealTimeIsUniversal /d 1 /t REG_DWORD /f`

## Dual Boot from the bootloader

- boot into linux
- `bootctl update`
- uncomment entries in `/efi/loader/loader.conf` 
- reboot and check both works at this stage

## Encrypt Windows

>Notes:
>   - On its own, having the TPM be the source of truth for *automatically* decrypting the Windows disk may or not may be desirable depending on your use case, as this means that:
> 	  - You can boot into Windows without any "guards": this increases the attack surface; i.e. if a vulnerability is discovered at the login screen level (that happened in the past), a TPM source of truth would still be exploitable.
> 	  - You would not be able to decrypt the disk offline, on another computer for example, without the recovery key. This may or may not be what you want. Given how often SSDs can fail, being able to read the disk with simply a password is, in our opinion, desirable.
>  - Depending on the TPM implementation, and generously generalizing (as we understand it), the hash of the bootloader may result in being one of the component to unlock a Bitlocker encrypted disk. This is in our case undesirable, since updating our bootloader would mean preventing the Windows encrypted disks to decrypt without the recovery key (some bootloaders have janky experimental tricks up their sleeves; we don't consider this to be desirable at the time of writing).
> 
>For the reasons stated above, this guide will therefore show the steps to enable a Bitlocker disk to unlock *solely* with a password.

- OPTIONAL: to read this drive offline with only a password (bypassing TPM requirements / need for the recovery key file)
	- Open: Local Group Policy Editor
	- Computer Configuration -> Administrative Templates -> Windows Components -> BitLocker Drive Encryption -> Operating System Drives
	- Open: Require additional authentication at startup
	- Change "Not Configured" to "Enabled".
	- Forbid TPM in the below drop-down menu.

- Bitlocker time!
	- Settings => Manage Bitlocker
	- Follow the GUI. Set up a password, (and only a password, should that be your wish) while also getting your recovery keys offline to a USB drive (or synced to a Microsoft, should that again be your wish)

## OPTIONAL: Sanity check to read the Windows drives offline

- boot into linux
- `sudo cryptsetup open --type bitlk <Windows partition> windows`
- `mount /dev/mapper/<windows> /mnt`
>	You should be able to read it with only the password. Should you need to read this drive from another computer, this exact command proves you only need the password to read it. Again, this may or may not be what you want.

## Secure boot

- boot into linux 
- 
```sh
sudo -i

pacman -S efitools sbsigntools

mkdir -p /etc/secureboot
chmod 700 /etc/secureboot
cd /etc/secureboot

# Generate our own "organization"'s GUID
uuidgen --random > GUID.txt

# Generate the Platform Key
openssl req -newkey rsa:4096 -nodes -keyout PK.key -new -x509 -sha256 -days 3650 -subj "/CN=<my Platform Key>/" -out PK.crt
openssl x509 -outform DER -in PK.crt -out PK.cer
cert-to-efi-sig-list -g "$(< GUID.txt)" PK.crt PK.esl
sign-efi-sig-list -g "$(< GUID.txt)" -k PK.key -c PK.crt PK PK.esl PK.auth

# Sign an empty file to allow removal of the current PK later on during enrollment
sign-efi-sig-list -g "$(< GUID.txt)" -c PK.crt -k PK.key PK /dev/null rm_PK.auth

# Generate the Key Exchange Key
openssl req -newkey rsa:4096 -nodes -keyout KEK.key -new -x509 -sha256 -days 3650 -subj "/CN=<my Key Exchange Key>/" -out KEK.crt
openssl x509 -outform DER -in KEK.crt -out KEK.cer
cert-to-efi-sig-list -g "$(< GUID.txt)" KEK.crt KEK.esl
sign-efi-sig-list -g "$(< GUID.txt)" -k PK.key -c PK.crt KEK KEK.esl KEK.auth

# Generate the Database Key
openssl req -newkey rsa:4096 -nodes -keyout db.key -new -x509 -sha256 -days 3650 -subj "/CN=<my Signature Database key>/" -out db.crt
openssl x509 -outform DER -in db.crt -out db.cer
cert-to-efi-sig-list -g "$(< GUID.txt)" db.crt db.esl
sign-efi-sig-list -g "$(< GUID.txt)" -k KEK.key -c KEK.crt db db.esl db.auth

# Sanity check: 17 files; 3 quintuples of key (db, PK, KEK) + GUID.txt + rm_PK.auth
ls

# Get Microsoft's own keys
mkdir -p windows
cd windows

curl -L https://go.microsoft.com/fwlink/?LinkId=321185 > MS_KEK.crt
curl -L https://go.microsoft.com/fwlink/p/?linkid=321192 > MS_db.crt
curl -L https://go.microsoft.com/fwlink/p/?linkid=321194 > MS_db_uefi.crt


# Add Microsoft's keys to our own database
echo "77fa9abd-0359-4d32-bd60-28f4e78f784b" > MS_GUID.txt

sbsiglist --owner "$(< MS_GUID.txt)" --type x509 --output MS_db.esl MS_db.crt
sbsiglist --owner "$(< MS_GUID.txt)" --type x509 --output MS_db_uefi.esl MS_db_uefi.crt
cat MS_db.esl MS_db_uefi.esl > MS_db_full.esl

sbsiglist --owner "$(< MS_GUID.txt)" --type x509 --output MS_KEK.esl MS_KEK.crt
sign-efi-sig-list -a -g "$(< MS_GUID.txt)" -k ../KEK.key -c ../KEK.crt db MS_db_full.esl add_MS_db_full.auth

sign-efi-sig-list -a -g "$(< MS_GUID.txt)" -k ../PK.key -c ../PK.crt KEK MS_KEK.esl add_MS_KEK.auth

# Methods varies to enroll the keys. Some only requires the .auth, others require .esl, .cer and .auth files. Some firmware can do it for you from their UI. Refer to the documentation of the firmware.
# We will enroll the keys at the very end.
# You probably want to make the keys available to the UEFI by copying the keys to the unencrypted UEFI partition for later enrollment.
mkdir -p /efi/keys
cp add_MS_KEK.auth add_MS_db_full.auth /efi/keys

# Setup automatic resigning
nvim /etc/pacman.d/hooks/99-sbsign-uki.hook
	[Trigger]  
	Operation = Install  
	Operation = Upgrade  
	Type = Path  
	Target = usr/lib/modules/*/vmlinuz  
	Target = usr/lib/initcpio/*
	
	[Action]  
	Description = Signing Unified Kernel Image...  
	When = PostTransaction  
	Exec = /usr/bin/sbsign --key /etc/secureboot/db.key --cert /etc/secureboot/db.crt --output /efi/EFI/Linux/arch.efi /efi/EFI/Linux/arch.efi  
	NeedsTargets

nvim /etc/pacman.d/hooks/99-sbsign-systemd.hook
	[Trigger]  
	Operation = Install  
	Operation = Upgrade  
	Type = Package  
	Target = systemd
	
	[Action]  
	Description = Signing systemd-boot...  
	When = PostTransaction  
	Exec = /usr/bin/sbsign --key /etc/secureboot/db.key --cert /etc/secureboot/db.crt /usr/lib/systemd/boot/efi/systemd-bootx64.efi
	NeedsTargets


# Trigger a dummy update to trigger the above hooks
pacman -S linux systemd
bootctl install
systemctl enable --now systemd-boot-update.service



# Make your own keys available to your firmware for enrollment
mkdir -p /efi/keys
cp rm_PK.auth PK.auth KEK.auth db.auth /efi/keys

# Enroll your keys. Method will varies depending on your firmware.

# /!\ Enroll your own PK *last*, as this action activates Secure Boot.
# If the firmware complains about enrolling your own PK, enroll rm_PK.auth first to set Secure Boot in setup mode, then enroll PK.auth  

# /!\ On some systems, removing the OEM keys can break stuff. You can dump them if needed and sign them with your own keys as shown for the Microsoft's ones.


# Example for x64 architecture with KeyTool
sbsign --key db.key --cert db.crt --output /<some mounted FAT32 flash drive>/EFI/BOOT/BOOTX64.EFI /usr/share/efitools/efi/KeyTool.efi

# Boot from this flash drive and follow instructions (not done on our examples, the firmware was nice enough in our case)
```

- Don't forget to only allow the Linux Bootloader in the UEFI's boot order, and to set a password.

## You're done!

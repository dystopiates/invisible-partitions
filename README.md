# Plausibly Deniable Partition Script

This script generates offsets and disk encryption keys given a password and a salt.

One interesting property of this is that, if you choose your salt carefully, you can generate multiple offsets that are far enough away from each other to have several hidden, encrypted, plausibly deniable partitions. i.e., you can have one partition start 10% of the way through the block device, and a second one starting 15% of the way through, without an attacker being able to prove the existence of either. With this, you can "reveal" one partition with one password under duress, while keeping another partition(s) hidden. If you randomize the block device beforehand, then the presence of any other partitions cannot be proven.

This script asks the user for several passwords and desired partition offsets, and then brute forces different salts until it finds one that generates the desired partition details. It then spits out an unlock script that has the saved salt, that can be used to later decrypt and set up filesystems. If an attacker is able to see this unlock script, all they can show is that you likely have hidden partitions on some device; they won't know what device, or how many partitions, and without the device itself, they can't even begin trying to brute-force your password(s).

#### If you only want to see how I do things, head straight to `prepare.py`


## !!!! Warning !!!!

I am not an expert in cryptography! This is a hobby project!

I can't guarantee my beliefs about this code are correct! Use at your own risk.


### Using the preparation script

Usage (user input in bold):
<pre>
$ <b>./prepare.py &lt;block_device&gt; &lt;unlock_script.py&gt;</b>
</pre>

Asks the user for partitions they desire on `block_device`, finds a good enough salt, and saves an unlock script to `unlock_script.py`. No data is written to `block_device`.

Example:
<pre>
$ <b>sudo python3 prepare.py /dev/sdb unlock.py</b>
</pre>

The script will then ask you for details on the partitions you want.

Note that when it asks for block offsets, you can enter locations like <b>5M</b>, <b>4.5G</b>, etc to specify offsets in megabytes or gigabytes instead of 4096-bit blocks. Accepted postfixes are <b>B</b>, <b>K</b>, <b>M</b>, <b>G</b>, <b>T</b>, and <b>P</b>.

Once an unlock script is generated, you should use it to open and set up your hidden filesystems.


### Using the unlock script

Unlock script usage:
<pre>
$ <b>./unlock.py &lt;block_device&gt; &lt;mapping_name&gt;</b>
</pre>

Derives the offset and crypto key, then uses `cryptsetup` to open the device. This likely needs root.

Example:
<pre>
$ <b>sudo python3 unlock.py /dev/sdb crypt_part</b>
Password for blob [crypt_part]: 
Unlocking blob [crypt_part]...
Partition starts at block 1270 (4.961M)
Done unlocking blob [crypt_part]

$ <b>lsblk</b>
NAME         MAJ:MIN RM   SIZE RO TYPE  MOUNTPOINTS
...
sda            7:0    0    10M  0 loop  
└─crypt_part 254:2    0     5M  0 crypt
...
</pre>

With this done, you can now create your hidden filesystems. For example:

<pre>
$ <b>sudo mkfs.fat /dev/mapper/crypt_part</b> 
</pre>

I suggest using FAT, or another filesystem that doesn't write much past the start of the partition, to avoid corrupting later hidden partitions.


## Usage Demo

What follows is a full shell session in which I create several hidden partitions in a 10 MB "block" device file I make, named `blob`. I make 3 partitions, with the passwords `AAAA`, `BBBB`, and `CCCC`, respectively. After creating the unlock script, I then create several filesystems in their respective hidden partitions.

Along with this readme demo, I've also included the `unlock.py` script and seemingly random `blob` in this git repo. If you download my `unlock.py` and `blob`, feel free to try it out.

Note: italicized text doesn't show up when running, it's simply an annotation.

<pre>
$ <b>ls</b>
mnt  prepare.py

$ <b>dd if=/dev/urandom of=blob bs=1024 count=10240</b>  <i># make a 10MB blob</i>
10240+0 records in
10240+0 records out
10485760 bytes (10 MB, 10 MiB) copied, 0.211578 s, 49.6 MB/s

$ <b>ls</b>  <i># Show the blob, the directory "mnt", and the prep script</i>
blob  mnt/  prepare.py

$ <b>python3 prepare.py blob unlock.py</b>  <i># Prepare a salt with the desired properties</i>
Device is 2560 blocks (10M)
Getting details for partition 1...
Password for partition 1: <i>AAAA</i>
Re-enter: <i>AAAA</i>
Starting location for partition 1: <b>5M</b>
Target offset for partition 1: 1280 (5M)
Add more partitions? (Y/n) <b>y</b>

Getting details for partition 2...
Password for partition 2: <i>BBBB</i>
Re-enter: <i>BBBB</i>
Starting location for partition 2: <b>2.5M</b>
Target offset for partition 2: 640 (2.5M)
Add more partitions? (Y/n) <b>y</b>

Getting details for partition 3...
Password for partition 3: <i>CCCC</i>
Re-enter: <i>CCCC</i>
Starting location for partition 3: <b>7.5M</b>
Target offset for partition 3: 1920 (7.5M)
Add more partitions? (Y/n) <b>n</b>

Targeting the following partitions...
    Partition 1: Block 1280 (5M)
    Partition 2: Block 640 (2.5M)
    Partition 3: Block 1920 (7.5M)

It is hard to target offsets exactly, so an acceptable deviation can be set.
This tool searches for offsets such that the total cumulative deviations
are less than n blocks.
Maximum cumulative offset deviation: <b>0.4M</b> 
Using maximum cumulative deviation 102 (408K)
Found a deviation of 2548...
Found a deviation of 1840...
Found a deviation of 1177...
Found a deviation of 595...
Found a deviation of 544...
Found a deviation of 405...
Found a deviation of 191...
Found a deviation of 18...
Found a salt with cumulative deviation 18 (72K).
The salt has the following partitions...
    Partition 1: Block 1277 (4.988M)
    Partition 2: Block 647 (2.527M)
    Partition 3: Block 1928 (7.531M)
Accept this partition layout and generate an unlocker? (Y/n) <b>y</b>
Saved unlocker script to unlock.py
</pre>

With this, we now have an `unlock.py` script! Now, use it to create the mappings and prepare filesystems.

<pre>
$ <b>sudo python3 unlock.py blob AAAA_crypt</b>
Password for blob [AAAA_crypt]: <i>AAAA</i>
Unlocking blob [AAAA_crypt]...
Partition starts at block 1270 (4.961M)
Done unlocking blob [AAAA_crypt]

$ <b>lsblk</b>
NAME         MAJ:MIN RM   SIZE RO TYPE  MOUNTPOINTS
loop0          7:0    0    10M  0 loop  
└─AAAA_crypt 254:2    0     5M  0 crypt 
...

$ <b>sudo mkfs.fat /dev/mapper/AAAA_crypt</b> 
mkfs.fat 4.2 (2021-01-31)

$ <b>sudo mount /dev/mapper/AAAA_crypt mnt</b>
$ <b>sudo touch mnt/hidden-file</b>
$ <b>sudo umount mnt</b>
$ <b>sudo cryptsetup close /dev/mapper/AAAA_crypt</b>  <i># Important! Remember to close your vault!</i>

$ <b>sudo python3 unlock.py blob BBBB_crypt</b>
<i># ... then repeat setup for the other hidden partitions, BBBB and CCCC</i>
</pre>

Note, that you can even have unencrypted partitions at the very front of the drive!

<pre>
$ <b>mkdir plain</b>

$ <b>sudo mount blob plain</b>

$ <b>ls plain</b>
turtles-clear.txt

$ <b>cat plain/turtles-clear.txt</b> 
It's turtles all the day down
</pre>
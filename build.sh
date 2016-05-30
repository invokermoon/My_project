#!/bin/bash
usage()
{
	echo "$0 {-h} {-i} {-r}"
	echo " -h: help"
	echo " -c: compile the code"
	echo " -i: insmod the moudle"
	echo " -r: rmmmod the module"
	echo " -C: clean the code"
	echo " defalut: compile project"
	exit 0
}

out_dir=`pwd`/out
funcs_en=0

ROOT_UID=0

if [ "$UID" -eq "$ROOT_UID" ]
then
	echo "You are root."
else
	echo "Please login as root"
	exit 0
fi

while getopts ":hcitrC"  opt
do
	case "$opt" in
		h)
			usage;
			;;
		c)
			make -j12
			chmod +x $out_dir/qeexo.ko
			;;
		t)
			#gnome-terminal --title "LOG_OUTPUT" -x bash -c "while true; do sudo cat /proc/kmsg; sudo sleep 1; done; exec bash;"
			;;
		i)
			echo "login as root,input the passwd"
			#sudo gnome-terminal --title "LOG_OUTPUT" -x bash -c "tail -f /var/log/kern.log; exec bash;"
			funcs_en=1;
			shift;
			;;
		r)
			sudo rmmod qeexo
            ;;
		C)
			make clean
			;;
		?)
			;;
	esac
done

if [ $funcs_en -eq 1 ]; then
	sleep 1
	sudo rmmod qeexo >/dev/null 2>&1
	sudo dmesg -C
	sleep 1
	#sudo insmod $out_dir/qeexo.ko funcs=$*
	sudo insmod $out_dir/qeexo.ko funcs=sys_clone,sys_read
	echo "Insmoding...$*"
	echo "**********************************************************"
	echo "Following is log by dmesg and printk"
	echo ""
	dmesg
	sleep 1
	echo "**********************************************************"
	echo "Get the memleak infos from moudle test1 and test2"
	echo ""
	cat /sys/class/qeexo/profiler/memleaks
	echo "**********************************************************"
	echo "Get the qattrs infos by sys_clone and sys_read"
	echo ""
	cat /sys/class/qeexo/profiler/qattrs
	echo "**********************************************************"
	echo "Also, you can read them again:"
	echo ""
	echo "cat /sys/class/qeexo/profiler/qattrs"
	echo "cat /sys/class/qeexo/profiler/memleaks"
fi


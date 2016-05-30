#!/bin/bash
usage()
{
	echo "$0 {-h} {-e} {-r g[debug os]}"
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

while getopts ":hcitrC"  opt
do
	case "$opt" in
		h)
			usage;
			;;
		c)
			make -j12
			chmod +x $out_dir/qkrp.ko
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
			sudo rmmod	qkrp
            ;;
		C)
			make clean
			;;
		?)
			;;
	esac
done

if [ $funcs_en -eq 1 ]; then
	sudo rmmod qkrp >/dev/null 2>&1
	dmesg -C
	sleep 1
	echo "Insmoding...$*"
	sudo insmod $out_dir/qkrp.ko funcs=$*
	dmesg
fi


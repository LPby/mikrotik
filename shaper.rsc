#Settings
######################################################
:local UPLOADSPEED ("1024000");
:local DOWNLOADSPEED ("10240000");
:local WANINTERFACE ("pptp-wan");
:local TCPPORTS ("22,3306,53");
:local UDPPORTS ("53");

# Calculated vars
######################################################
:local USERCOUNT ( [/ip firewall address-list print count-only where list=Users] + 1 );
:local UPBUF ($UPLOADSPEED/10);
:local DOWNBUF ($DOWNLOADSPEED/20);
:local UPLOADLIMIT ( ( $UPLOADSPEED - $UPBUF ) / $USERCOUNT);
:local DOWNLOADLIMIT ($DOWNLOADSPEED / 2 / $USERCOUNT);
:local IP;

#Make mangle rules
/ip firewall mangle remove [find where chain=forward out-interface="$WANINTERFACE"];
/ip firewall mangle add action=jump chain=forward connection-state=new comment="out con $WANINTERFACE" jump-target="upload-con-$WANINTERFACE" out-interface="$WANINTERFACE";        
/ip firewall mangle add action=jump chain=forward connection-state=established,related comment="out packet $WANINTERFACE" jump-target="upload-packet-$WANINTERFACE" out-interface="$WANINTERFACE";        

/ip firewall mangle remove [find where chain=forward in-interface="$WANINTERFACE"];
/ip firewall mangle add action=jump chain=forward comment="in $WANINTERFACE" in-interface="$WANINTERFACE" jump-target="download-packet-$WANINTERFACE";

/ip firewall mangle remove [find where chain=input in-interface="$WANINTERFACE"] ;
/ip firewall mangle add chain=input action=mark-packet new-packet-mark="input-$WANINTERFACE" passthrough=no in-interface="$WANINTERFACE";

/ip firewall mangle remove [find where chain=output out-interface="$WANINTERFACE"] ;
/ip firewall mangle add chain=output action=mark-packet new-packet-mark="output-$WANINTERFACE" passthrough=no out-interface="$WANINTERFACE";


#Upload connections
/ip firewall mangle remove  [find where chain="upload-con-$WANINTERFACE"];
:foreach i in=[/ip firewall address-list find list="Users"] do={ 
    :set IP [/ip firewall address-list get $i address];
    /ip firewall mangle add action=mark-connection chain="upload-con-$WANINTERFACE" new-connection-mark="connection-down-$WANINTERFACE-$IP" src-address="$IP" out-interface="$WANINTERFACE" comment="$WANINTERFACE-$IP";
}
/ip firewall mangle add action=mark-connection chain="upload-con-$WANINTERFACE" comment="$WANINTERFACE-protocols" out-interface="$WANINTERFACE" dst-port="$TCPPORTS" new-connection-mark="connection-down-$WANINTERFACE-protocols" protocol=tcp;
/ip firewall mangle add action=mark-connection chain="upload-con-$WANINTERFACE" comment="$WANINTERFACE-protocols" out-interface="$WANINTERFACE" dst-port="$UDPPORTS" new-connection-mark="connection-down-$WANINTERFACE-protocols" protocol=udp;

#Upload packets
/ip firewall mangle remove  [find where chain="upload-packet-$WANINTERFACE"];
:foreach i in=[/ip firewall address-list find list="Users"] do={ 
    :set IP [/ip firewall address-list get $i address];
    /ip firewall mangle add action=mark-packet chain="upload-packet-$WANINTERFACE" src-address="$IP" out-interface="$WANINTERFACE" new-packet-mark="packet-up-$WANINTERFACE-$IP" comment="$WANINTERFACE-$IP" passthrough=no;
}
/ip firewall mangle add action=mark-packet chain="upload-packet-$WANINTERFACE" out-interface="$WANINTERFACE" new-packet-mark="packet-up-$WANINTERFACE-else" comment="$WANINTERFACE-else" passthrough=no;

#Download packets
/ip firewall mangle remove  [find where chain="download-packet-$WANINTERFACE"];
/ip firewall mangle add action=mark-packet chain="download-packet-$WANINTERFACE" comment="$WANINTERFACE-protocols" connection-mark="connection-down-$WANINTERFACE-protocols" in-interface="$WANINTERFACE" new-packet-mark="packet-down-$WANINTERFACE-protocols" passthrough=no;
:foreach i in=[/ip firewall address-list find list="Users"] do={ 
    :set IP [/ip firewall address-list get $i address];
    /ip firewall mangle add action=mark-packet chain="download-packet-$WANINTERFACE" connection-mark="connection-down-$WANINTERFACE-$IP" in-interface="$WANINTERFACE" new-packet-mark="packet-down-$WANINTERFACE-$IP" comment="$WANINTERFACE-$IP" passthrough=no;
}
/ip firewall mangle add action=mark-packet chain="download-packet-$WANINTERFACE" in-interface="$WANINTERFACE" new-packet-mark="packet-down-$WANINTERFACE-else" comment="$WANINTERFACE-else" passthrough=no;


#Make queue tree download
/queue tree remove [find where name~"down-$WANINTERFACE"];
/queue tree add limit-at="$DOWNLOADSPEED" max-limit="$DOWNLOADSPEED" name="down-$WANINTERFACE" parent=global;
/queue tree add limit-at=($DOWNLOADSPEED / 2) max-limit=($DOWNLOADSPEED - $DOWNBUF) name="down-$WANINTERFACE-users" parent="down-$WANINTERFACE" queue=download;
/queue tree add limit-at=($DOWNLOADSPEED / 2 - $DOWNBUF) max-limit=($DOWNLOADSPEED - $DOWNBUF) name="down-$WANINTERFACE-protocols" packet-mark="packet-down-$WANINTERFACE-protocols" parent="down-$WANINTERFACE" queue=download priority=2;
/queue tree add limit-at=$DOWNBUF max-limit=($DOWNLOADSPEED - $DOWNBUF) name="down-$WANINTERFACE-else" packet-mark="packet-down-$WANINTERFACE-else" parent="down-$WANINTERFACE" queue=download;
:foreach i in=[/ip firewall address-list find list="Users"] do={ 
    :set IP [/ip firewall address-list get $i address];
    /queue tree add limit-at=$DOWNLOADLIMIT max-limit=($DOWNLOADSPEED - $DOWNBUF) name="down-$WANINTERFACE-$IP" packet-mark="packet-down-$WANINTERFACE-$IP" parent="down-$WANINTERFACE-users" queue=download priority=3;
}
/queue tree add limit-at=$DOWNLOADLIMIT max-limit=($DOWNLOADSPEED - $DOWNBUF) name="down-$WANINTERFACE-local" packet-mark="input-$WANINTERFACE" parent="down-$WANINTERFACE-users" queue=download priority=1;

#Make queue tree upload
/queue tree remove [find where name~"up-$WANINTERFACE"];
/queue tree add limit-at="$UPLOADSPEED" max-limit="$UPLOADSPEED" name="up-$WANINTERFACE" parent=global;
/queue tree add limit-at=$UPBUF max-limit=($UPLOADSPEED - $UPBUF) name="up-$WANINTERFACE-else" packet-mark="packet-up-$WANINTERFACE-else" parent="up-$WANINTERFACE" queue=upload;
:foreach i in=[/ip firewall address-list find list="Users"] do={ 
    :set IP [/ip firewall address-list get $i address];
    /queue tree add limit-at=$UPLOADLIMIT max-limit=($UPLOADSPEED - $UPBUF) name="up-$WANINTERFACE-$IP" packet-mark="packet-up-$WANINTERFACE-$IP" parent="up-$WANINTERFACE" queue=upload priority=2;
}
/queue tree add limit-at=$UPLOADLIMIT max-limit=($UPLOADSPEED - $UPBUF) name="up-$WANINTERFACE-local" packet-mark="output-$WANINTERFACE" parent="up-$WANINTERFACE" queue=upload priority=1;

#APARTADO 1 (PORCENTAJE DE PAQUETES IP)
echo -e "APARTADO 1 (PORCENTAJE DE PAQUETES IP)"
tshark -r trazap3.pcap -T fields -e eth.type -e vlan.etype | awk '{
	if(($1 == 2048)||($2 == 2048))	
		n_ip = n_ip + 1;
}
END {
    print "\t*El porcentaje de paquetes IP es " 100*n_ip/NR "%";
}' 






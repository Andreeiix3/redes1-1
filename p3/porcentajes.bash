awk 'BEGIN{FS="\t";}
{	
	if ($2 == 2048 || $3 == 2048 ){
		n_ip = n_ip + 1;
 		if($14 == 6){
 			n_tcp = n_tcp + 1;}
 		if($14 == 17){
 			n_udp = n_udp + 1;}
 	}	
}
END {

	data = n_ip/NR;
	tcp = n_tcp/n_ip*100;
	udp = n_udp/n_ip*100;
    printf "\t*El porcentaje de paquetes IP es  %.4f %%\n", 100*data;
	print "\t De los cuales:";
	printf "\t\t*El %.4f %% son TCP\n", tcp;
	printf "\t\t*El %.4f %% son UDP\n", udp;
	printf "\t\t*El %.4f %% son OTROS\n", 100-tcp-udp; 
	printf "\t*El porcentaje de paquetes NO-IP es %.4f %%\n", 100*(1-data);
	
}' datos.txt

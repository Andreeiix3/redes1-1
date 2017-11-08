#Creacion del fichero con los datos que vamos a necesitar (la idea es que se generen aqui todos los datos que se vayan a utilizar
#en todos los puntos. Esto servira para ahorrar tiempo a la larga (las llamadas a tshark toman tiempo). Si al final no hubiera tantas
#puede que no haga falta este fichero!.

#Campos del fichero.
#	$1 LONGITUD DEL PAQUETE (bytes)                
#	$2 ETHTYPE
#	$3 VLANETYPE
#	$4 IP SOURCE DIR
#	$5 IP DEST DIR
#	$6 TCP SRC PORT
#	$7 TCP DEST PORT
#	$8 UDP SRC PORT
#	$9 UDP DEST PORT
#	$10
#	$11

  
tshark -r trazap3.pcap -T fields -e frame.len -e eth.type -e vlan.etype -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e udp.srcport -e udp.dstport > datos.txt 

######APARTADO 1 (PORCENTAJE DE PAQUETES IP)
echo -e "APARTADO 1: PORCENTAJE DE PAQUETES IP"
awk '{
	if(($2 == 2048)||($3 == 2048))	
		n_ip = n_ip + 1;
}
END {
	data = n_ip/NR
    print "\t*El porcentaje de paquetes IP es " 100*data "%";
	print "\t*El porcentaje de paquetes NO-IP es " 100*(1-data) "%";
}' datos.txt

######APARTADO 2 (TOP 10 IP/PUERTOS-ORIGEN/DESTINO-BYTES/PAQUETES)
echo -e "\nAPARTADO 2: TOPs 10"

#Direcciones IP origen nP = numero paquetes
#					   nB = numero bytes

echo -e "\n\t*TOP 10 IP Source (Numero de paquetes)"
awk 'BEGIN{ FS = "\t"; }
{
	if($4 != null){
		contadornP[$4] = contadornP[$4] + 1;
		contadornB[$4] = contadornB[$4] + $1;
	}
}
END {
	for (valor in contadornP) {
		print valor "\t" contadornP[valor] "\t" contadornB[valor];
	}
}' datos.txt > aux.txt

sort -t$'\t' -n -r -k2  aux.txt| head -n 10
echo -e "\n\t*TOP 10 IP Source (Numero de bytes)"
sort -t$'\t' -n -r -k3  aux.txt| head -n 10

#Te ahorro la busqueda:
#flags de Sort:
#-t fija el separador que distingue campos, como hemos impreso con \t pues pongo \t
#-n orden numerico
#-k? k de Kampo(o Kolumna), y el numero de la que quieras


#Direcciones IP dest nP = numero paquetes
#					   nB = numero bytes
  
echo -e "\n\t*TOP 10 IP Dest (Numero de paquetes)"
awk 'BEGIN{ FS = "\t"; }
{	
	if($5 != null){
		contadornP[$5] = contadornP[$5] + 1;
		contadornB[$5] = contadornB[$5] + $1;
	}
}
END {
	for (valor in contadornP) {
		print valor "\t" contadornP[valor] "\t" contadornB[valor];
	}
}' datos.txt > aux.txt

sort -t$'\t' -n -r -k2  aux.txt| head -n 10
echo -e "\n\t*TOP 10 Puerto IP Dest (Numero de bytes)"
sort -t$'\t' -n -r -k3  aux.txt| head -n 10


#Direcciones TCP Source

echo -e "\n\t*TOP 10 Puerto TCP Source (Numero de paquetes)"
awk 'BEGIN{ FS = "\t";}
{	if($6 != null){
		contadornP[$6] = contadornP[$6] + 1;
		contadornB[$6] = contadornB[$6] + $1;
	}
}
END {
	for (valor in contadornB) {
		print valor "\t" contadornP[valor] "\t" contadornB[valor];
	}
}' datos.txt > aux.txt

sort -t$'\t' -n -b -r -k2  aux.txt| head -n 10
echo -e "\n\t*TOP 10 Puertos TCP Source (Numero de bytes)"
sort -t$'\t' -n -r -k3  aux.txt| head -n 10


#Puertos TCP Dest

echo -e "\n\t*TOP 10 Puerto TCP Dest (Numero de paquetes)"
awk 'BEGIN{ FS = "\t";}
{	if($7 != null){
		contadornP[$7] = contadornP[$7] + 1;
		contadornB[$7] = contadornB[$7] + $1;
	}
}
END {
	for (valor in contadornB) {
		print valor "\t" contadornP[valor] "\t" contadornB[valor];
	}
}' datos.txt > aux.txt

sort -t$'\t' -n -b -r -k2  aux.txt| head -n 10
echo -e "\n\t*TOP 10 Puertos TCP Dest (Numero de bytes)"
sort -t$'\t' -n -r -k3  aux.txt| head -n 10


#Puertos UDP Source


echo -e "\n\t*TOP 10 Puerto UDP Source (Numero de paquetes)"
awk 'BEGIN{ FS = "\t";}
{	if($8 != null){
		contadornP[$8] = contadornP[$8] + 1;
		contadornB[$8] = contadornB[$8] + $1;
	}
}
END {
	for (valor in contadornB) {
		print valor "\t" contadornP[valor] "\t" contadornB[valor];
	}
}' datos.txt > aux.txt

sort -t$'\t' -n -b -r -k2  aux.txt| head -n 10
echo -e "\n\t*TOP 10 Puertos UDP Source (Numero de bytes)"
sort -t$'\t' -n -b -r -k3  aux.txt| head -n 10


#Puertos UDP Dest

echo -e "\n\t*TOP 10 Puerto UDP Dest (Numero de paquetes)"
awk 'BEGIN{ FS = "\t";}
{	if($9 != null){
		contadornP[$9] = contadornP[$9] + 1;
		contadornB[$9] = contadornB[$9] + $1;
	}
}
END {
	for (valor in contadornB) {
		print valor "\t" contadornP[valor] "\t" contadornB[valor];
	}
}' datos.txt > aux.txt

sort -t$'\t' -n -b -r -k2  aux.txt| head -n 10
echo -e "\n\t*TOP 10 Puerto UDP Dest (Numero de bytes)"
sort -t$'\t' -n -b -r -k3  aux.txt| head -n 10


rm datos.txt
rm aux.txt






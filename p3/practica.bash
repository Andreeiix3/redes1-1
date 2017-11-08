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

  
tshark -r trazap3.pcap -T fields -e frame.len -e eth.type -e vlan.etype -e ip.src -e ip.dst -e tcp.srcport -e tcp.srcport -e udp.srcport -e udp.srcport > datos.txt 

#APARTADO 1 (PORCENTAJE DE PAQUETES IP)
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

#APARTADO 2 (TOP 10 IP/PUERTOS-ORIGEN/DESTINO-BYTES/PAQUETES)
echo -e "\nAPARTADO 2: TOPs 10"

#Direcciones IP origen nP = numero paquetes

#ESTE Y EL DE ABAJO DAN NUMEROS QUE PARECEN RAZONABLES, HE COMPROBADO UN POCO CON WIRESHARK Y PARECE QUE ESTA BIEN

echo -e "\n\t*TOP 10 IP Source (Numero de paquetes)"
awk 'BEGIN{ FS = "\t"; }
{
	contadornP[$4] = contadornP[$4] + 1;
}
END {
	for (valor in contadornP) {
		print valor "\t" contadornP[valor];
	}
}' datos.txt > aux.txt

sort -t$'\t' -n -r -k2  aux.txt| head -n 10

#Te ahorro la busqueda:
#flags de Sort:
#-t fija el separador que distingue campos, como hemos impreso con \t pues pongo \t
#-n orden numerico
#-k? k de Kampo(o Kolumna), y el numero de la que quieras
#qde Head, -n para que imprima toda la fila


#Direcciones IP source nB = numero bytes

echo -e "\n\t*TOP 10 IP Source (Numero de bytes)"
awk 'BEGIN{ FS = "\t"};
{
	contadornB[$4] = contadornB[$4] + $1;
}
END {
	for (valor in contadornB) {
		print valor"\t"contadornB[valor];
	}
}' datos.txt > aux.txt

sort -t$'\t' -n -r -k2  aux.txt| head -n 10

#Direcciones IP dest nP = numero de paquetes

echo -e "\n\t*TOP 10 IP Dest (Numero de paquetes)"
awk 'BEGIN{ FS = "\t"; }
{
	contadornP[$5] = contadornP[$5] + 1;
}
END {
	for (valor in contadornP) {
		print valor "\t" contadornP[valor];
	}
}' datos.txt > aux.txt

sort -t$'\t' -n -r -k2  aux.txt| head -n 10

#Direcciones IP destino nB = numero bytes

echo -e "\n\t*TOP 10 IP Dest (Numero de bytes)"
awk 'BEGIN{ FS = "\t"};
{
	contadornB[$5] = contadornB[$5] + $1;
}
END {
	for (valor in contadornB) {
		print valor"\t"contadornB[valor];
	}
}' datos.txt > aux.txt

sort -t$'\t' -n -r -k2  aux.txt| head -n 10

#rm datos.txt
#rm aux.txt




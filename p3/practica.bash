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
#	$10 MAC SRC PORT
#	$11 MAC DEST PORT
#	$12 IP LENGTH (bytes)
#	$13 TIEMPO DESDE EL INICIO DE EJECUCION (segundos)
#	$14 PROTOCOLO IP

#Compilacion del fichero .c para la creación de ECDF (COMPROBAR EN MAQUINA VIRTUAL) 
gcc crearCDF.c -o crearCDF

tshark -r trazap3.pcap -T fields -e frame.len -e eth.type -e vlan.etype -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e udp.srcport -e udp.dstport -e eth.src -e eth.dst -e ip.len -e frame.time_relative -e ip.proto > datos.txt 

######APARTADO 1 (PORCENTAJE DE PAQUETES IP)
echo -e "##### APARTADO 1: PORCENTAJE DE PAQUETES IP #####\n"
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

######APARTADO 2 (TOP 10 IP/PUERTOS-ORIGEN/DESTINO-BYTES/PAQUETES)
echo -e "\n ##### APARTADO 2: TOPs 10 #####"

#Direcciones IP origen nP = numero paquetes
#					   nB = numero bytes

echo -e "\n\t*TOP 10 Direcciones IP Source (Orden: Numero de paquetes)\n"
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

echo -e "Formato: Direccion IP//Numero de Paquetes//Numero de bytes\n"  
sort -t$'\t' -n -r -k2  aux.txt| head -n 10
echo -e "\n\t*TOP 10 Direcciones IP Source (Orden: Numero de bytes)\n"
echo -e "Formato: Direccion IP//Numero de Paquetes//Numero de bytes\n"  
sort -t$'\t' -n -r -k3  aux.txt| head -n 10

#flags de Sort:
#-t fija el separador que distingue campos, como hemos impreso con \t pues pongo \t
#-n orden numerico
#-r reverse (orden inverso)
#-k? k de Kampo(o Kolumna), y el numero de la que quieras



#Direcciones IP dest nP = numero paquetes
#					 nB = numero bytes
  
echo -e "\n\t*TOP 10 Direcciones IP Dest (Orden: Numero de paquetes)\n"
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

echo -e "Formato: Direccion IP//Numero de Paquetes//Numero de bytes\n"  
sort -t$'\t' -n -r -k2  aux.txt| head -n 10
echo -e "\n\t*TOP 10 Direcciones IP Dest (Orden: Numero de bytes)\n"
echo -e "Formato: Direccion IP//Numero de Paquetes//Numero de bytes\n"  
sort -t$'\t' -n -r -k3  aux.txt| head -n 10


#Puertos TCP Source

echo -e "\n\t*TOP 10 Puerto TCP Source (Orden: Numero de paquetes)\n"
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

echo -e "Formato: Puerto TCP//Numero de Paquetes//Numero de bytes\n"  
sort -t$'\t' -n -b -r -k2  aux.txt| head -n 10
echo -e "\n\t*TOP 10 Puertos TCP Source (Orden: Numero de bytes)\n"
echo -e "Formato: Puerto TCP//Numero de Paquetes//Numero de bytes\n"  
sort -t$'\t' -n -r -k3  aux.txt| head -n 10


#Puertos TCP Dest

echo -e "\n\t*TOP 10 Puerto TCP Dest (Orden: Numero de paquetes)\n"
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

echo -e "Formato: Puerto TCP//Numero de Paquetes//Numero de bytes\n"  
sort -t$'\t' -n -b -r -k2  aux.txt| head -n 10
echo -e "\n\t*TOP 10 Puertos TCP Dest (Orden: Numero de bytes)\n"
echo -e "Formato: Puerto TCP//Numero de Paquetes//Numero de bytes\n"  
sort -t$'\t' -n -r -k3  aux.txt| head -n 10


#Puertos UDP Source


echo -e "\n\t*TOP 10 Puerto UDP Source (Orden: Numero de paquetes)\n"
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

echo -e "Formato: Puerto UDP//Numero de Paquetes//Numero de bytes\n"  
sort -t$'\t' -n -b -r -k2  aux.txt| head -n 10
echo -e "\n\t*TOP 10 Puertos UDP Source (Orden: Numero de bytes)\n"
echo -e "Formato: Puerto UDP//Numero de Paquetes//Numero de bytes\n"  
sort -t$'\t' -n -b -r -k3  aux.txt| head -n 10


#Puertos UDP Dest

echo -e "\n\t*TOP 10 Puerto UDP Dest (Orden: Numero de paquetes)\n"
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

echo -e "Formato: Puerto UDP//Numero de Paquetes//Numero de bytes\n"  
sort -t$'\t' -n -b -r -k2  aux.txt| head -n 10 
echo -e "\n\t*TOP 10 Puerto UDP Dest (Orden: Numero de bytes)\n"
echo -e "Formato: Puerto UDP//Numero de Paquetes//Numero de bytes\n"  
sort -t$'\t' -n -b -r -k3  aux.txt| head -n 10 


echo -e "\n##### APARTADO 3: ECDF Tamanos a nivel 2 #####\n"
#ECDF de tamaño paquetes a nivel 2. MAC Source.
#Filtro MAC = 00:11:88:CC:33:F8.

echo -e "\t*Generando ECDF de tamaño de paquetes a nivel 2 Source y Dest.\n\t\tFiltro MAC = 00:11:88:CC:33:F8"
awk 'BEGIN{ FS = "\t";}
{	if($10 == "00:11:88:cc:33:f8"){
		contadornP[$1] = contadornP[$1] + 1;
	}
}
END {
	for (valor in contadornP) {
		print valor "\t" contadornP[valor];
	}
}' datos.txt > aux.txt


#LLamada a crearCDF

./crearCDF


awk 'BEGIN{ FS = "\t";}
{	if($1 != null){
		contadornP[$1] = $2 + anterior;        
		anterior = contadornP[$1];
		total = total + $2;
	}
}
END {
	for (valor in contadornP) {
		print valor "\t" contadornP[valor]/total;
	}
}' salida.txt | sort -n > eth_mac_sourceECDF.txt

#ECDF de tamaño paquetes a nivel 2. MAC Dest.
#Filtro MAC = 00:11:88:CC:33:F8.

awk 'BEGIN{ FS = "\t";}
{	if($11 == "00:11:88:cc:33:f8"){
		contadornP[$1] = contadornP[$1] + 1;
	}
}
END {
	for (valor in contadornP) {
		print valor "\t" contadornP[valor];
	}
}' datos.txt > aux.txt


#LLamada a crearCDF

./crearCDF


awk 'BEGIN{ FS = "\t";}
{	if($1 != null){
		contadornP[$1] = $2 + anterior;
		anterior = contadornP[$1];
		total = total + $2;
	}
}
END {
	for (valor in contadornP) {
		print valor "\t" contadornP[valor]/total;
	}
}' salida.txt | sort -n > eth_mac_destECDF.txt


gnuplot << EOF
set title "ECDF Tamano paquetes a nivel 2. MAC = 00:11:88:CC:33:F8"
set xlabel "Tamano paquetes (bytes)"
set ylabel "Probabilidad"
unset label
unset key
set term png
set output "./plots/tamanio_mac.png"
plot "eth_mac_destECDF.txt" using 1:2 title 'Dest' with steps, "eth_mac_sourceECDF.txt" using 1:2 title 'Source' with steps
EOF

echo -e "\n\tECDF generado!"

#ECDF de tamaño paquetes HTTP a nivel 3. TCP Source.
#Filtro TCP = 80.

echo -e "\n##### APARTADO 4: ECDF Tamanos de paquetes HTTP a nivel 3 #####\n"
echo -e "\t*Generando ECDF de tamaño paquetes HTTP a nivel 3.\n\t\tFiltro TCP = 80"
awk 'BEGIN{ FS = "\t";}
{	if($6 == 80){
		contadornP[$12] = contadornP[$12] + 1;
	}
}
END {
	for (valor in contadornP) {
		print valor "\t" contadornP[valor];
	}
}' datos.txt > aux.txt


#LLamada a crearCDF

./crearCDF


awk 'BEGIN{ FS = "\t";}
{	if($1 != null){
		contadornP[$1] = $2 + anterior;
		anterior = contadornP[$1];
		total = total + $2;
	}
}
END {
	for (valor in contadornP) {
		print valor "\t" contadornP[valor]/total;
	}
}' salida.txt | sort -n > http_tcp_sourceECDF.txt



#ECDF de tamaño paquetes HTTP a nivel 3. TCP Dest.
#Filtro TCP = 80.

awk 'BEGIN{ FS = "\t";}
{	if($7 == 80){
		contadornP[$12] = contadornP[$12] + 1;
	}
}
END {
	for (valor in contadornP) {
		print valor "\t" contadornP[valor];
	}
}' datos.txt > aux.txt


#LLamada a crearCDF

./crearCDF


awk 'BEGIN{ FS = "\t";}
{	if($1 != null){
		contadornP[$1] = $2 + anterior;
		anterior = contadornP[$1];
		total = total + $2;
	}
}
END {
	for (valor in contadornP) {
		print valor "\t" contadornP[valor]/total;
	}
}' salida.txt | sort -n > http_tcp_destECDF.txt


gnuplot << EOF
set title "ECDF Tamano paquetes HTTP a nivel 3. TCP Dest = 80"
set xlabel "Tamano paquetes (bytes)"
set ylabel "Probabilidad"
unset label
unset key
set term png
set output "./plots/tamanio_http.png"
plot "http_tcp_destECDF.txt" using 1:2 title 'Dest' with steps, "http_tcp_sourceECDF.txt" using 1:2 title 'Source' with steps
EOF

echo -e "\n\tECDF generado!"



echo -e "\n##### APARTADO 5: ECDF Tamanos de paquetes DNS a nivel 3 #####\n"
#ECDF de tamaño paquetes DNS nivel 3. UDP Source.
#Filtro UDP = 53.

echo -e "\t*Generando ECDF de tamaño paquetes DNS a nivel 3.\n\t\tFiltro UDP = 53"
awk 'BEGIN{ FS = "\t";}
{	if($8 == 53){
		contadornP[$12] = contadornP[$12] + 1;
	}
}
END {
	for (valor in contadornP) {
		print valor "\t" contadornP[valor];
	}
}' datos.txt > aux.txt


#LLamada a crearCDF

./crearCDF


awk 'BEGIN{ FS = "\t";}
{	if($1 != null){
		contadornP[$1] = $2 + anterior;
		anterior = contadornP[$1];
		total = total + $2;
	}
}
END {
	for (valor in contadornP) {
		print valor "\t" contadornP[valor]/total;
	}
}' salida.txt | sort -n > dns_udp_sourceECDF.txt


#ECDF de tamaño paquetes DNS nivel 3. UDP Dest.
#Filtro UDP = 53.

echo -e "\n\t*Generando ECDF de tamaño paquetes DNS a nivel 3. UDP Dest.\n\t\tFiltro UDP = 53"
awk 'BEGIN{ FS = "\t";}
{	if($9 == 53){
		contadornP[$12] = contadornP[$12] + 1;
	}
}
END {
	for (valor in contadornP) {
		print valor "\t" contadornP[valor];
	}
}' datos.txt > aux.txt


#LLamada a crearCDF

./crearCDF


awk 'BEGIN{ FS = "\t";}
{	if($1 != null){
		contadornP[$1] = $2 + anterior;
		anterior = contadornP[$1];
		total = total + $2;
	}
}
END {
	for (valor in contadornP) {
		print valor "\t" contadornP[valor]/total;
	}
}' salida.txt | sort -n > dns_udp_destECDF.txt

gnuplot << EOF
set title "ECDF Tamano paquetes DNS a nivel 3. UDP Dest = 53"
set xlabel "Tamano paquetes (bytes)"
set ylabel "Probabilidad"
unset label
unset key
set term png
set output "./plots/tamanio_dns.png"
plot "dns_udp_destECDF.txt" using 1:2 title 'Dest' with steps, "dns_udp_sourceECDF.txt" using 1:2 title 'Source' with steps
EOF

echo -e "\n\tECDF generado!"


echo -e "\n##### APARTADO 6: ECDF Interarrival Time de flujo TCP #####\n"
#ECDF de tiempo entre llegadas de paquetes TCP a nivel 3. IP Source.
#Filtro IP = 71.166.7.216. Protocolo TCP/IP = 0x06

echo -e "\t*Generando ECDF de tiempo entre llegadas de paquetes TCP a nivel 3.\n\t\tFiltro IP = 71.166.7.216. Protocolo TCP/IP = 0x06"
awk 'BEGIN{ FS = "\t";}
{	if($4 == "71.166.7.216" && $14 == 6){
		tiempo_actual = $13 - tiempo_anterior;
		contadornP[tiempo_actual] = contadornP[tiempo_actual] + 1;
		tiempo_anterior = $13;
	}
}
END {
	for (valor in contadornP) {
		printf "%f\t%f\n", valor, contadornP[valor];
	}
}' datos.txt > aux.txt


#LLamada a crearCDF

./crearCDF


awk 'BEGIN{ FS = "\t";}
{	if($1 != null){
		contadornP[$1] = $2 + anterior;
		anterior = contadornP[$1];
		total = total + $2;
	}
}
END {
	for (valor in contadornP) {
		print valor "\t" contadornP[valor]/total;
	}
}' salida.txt | sort -n > time_tcp_sourceECDF.txt


#ECDF de tiempo entre llegadas de paquetes TCP a nivel 3. IP Dest.
#Filtro IP = 71.166.7.216. Protocolo TCP/IP = 0x06



awk 'BEGIN{ FS = "\t";}
{	if($5 == "71.166.7.216" && $14 == 6){
		tiempo_actual = $13 - tiempo_anterior;
		contadornP[tiempo_actual] = contadornP[tiempo_actual] + 1;
		tiempo_anterior = $13;
	}
}
END {
	for (valor in contadornP) {
		printf "%f\t%f\n", valor, contadornP[valor];
	}
}' datos.txt > aux.txt


#LLamada a crearCDF

./crearCDF


awk 'BEGIN{ FS = "\t";}
{	if($1 != null){
		contadornP[$1] = $2 + anterior;
		anterior = contadornP[$1];
		total = total + $2;
	}
}
END {
	for (valor in contadornP) {
		print valor "\t" contadornP[valor]/total;
	}
}' salida.txt | sort -n > time_tcp_destECDF.txt

gnuplot << EOF
set title "Tiempo entre llegadas de paquetes TCP (Nivel 3). IP Dest = 71.166.7.216"
set xlabel "Tiempo entre llegadas (segundos)"
set logscale x
set ylabel "Probabilidad"
unset label
unset key
set term png
set output "./plots/interarrivaltime_tcp.png"
plot "time_tcp_destECDF.txt" using 1:2 title 'Dest' with steps, "time_tcp_sourceECDF.txt" using 1:2 title 'Source' with steps
EOF

echo -e "\n\tECDF generado!"



echo -e "\n##### APARTADO 7: ECDF Interarrival Time de flujo UDP #####\n"
#ECDF de tiempo entre llegadas de paquetes UDP a nivel 3. UDP Source.
#Filtro UDP = 4939

echo -e "\t*Generando ECDF de tiempo entre llegadas de paquetes UDP a nivel 3.UDP Source.\n\t\tFiltro UDP = 4939"

awk 'BEGIN{ FS = "\t";}
{	if($8 == 4939){
		tiempo_actual = $13 - tiempo_anterior;
		contadornP[tiempo_actual] = contadornP[tiempo_actual] + 1;
		tiempo_anterior = $13;
	}
}
END {
	for (valor in contadornP) {
		printf "%f\t%f\n", valor, contadornP[valor];
	}
}' datos.txt > aux.txt


#LLamada a crearCDF

./crearCDF


awk 'BEGIN{ FS = "\t";}
{	if($1 != null){
		contadornP[$1] = $2 + anterior;
		anterior = contadornP[$1];
		total = total + $2;
	}
}
END {
	for (valor in contadornP) {
		print valor "\t" contadornP[valor]/total;
	}
}' salida.txt | sort -n > time_udp_sourceECDF.txt

echo -e "\n\tAtencion, no hay ningun paquete que satisfaga el filtro. No se puede generar un ECDF."

#gnuplot << EOF
#set title "Tiempo entre llegadas de paquetes UDP (Nivel 3). Puerto #UDP Source = 4939"
#set xlabel "Tiempo entre llegadas (segundos)"
#set ylabel "Probabilidad"
#unset label
#unset key
#set term png
#set output "./plots/interarrivaltime_udp_source.png"
#plot "time_udp_sourceECDF.txt" using 1:2 with steps
#EOF
#echo -e "\n\tECDF generado!"


#ECDF de tiempo entre llegadas de paquetes UDP a nivel 3. UDP Dest.
#Filtro UDP = 4939

echo -e "\n\t*Generando ECDF de tiempo entre llegadas de paquetes UDP a nivel 3. UDP Dest.\n\t\tFiltro UDP = 4939"

awk 'BEGIN{ FS = "\t";}
{	if($9 == 4939){
		tiempo_actual = $13 - tiempo_anterior;
		contadornP[tiempo_actual] = contadornP[tiempo_actual] + 1;
		tiempo_anterior = $13;
	}
}
END {
	for (valor in contadornP) {
		printf "%f\t%f\n", valor, contadornP[valor];
	}
}' datos.txt > aux.txt


#LLamada a crearCDF

./crearCDF


awk 'BEGIN{ FS = "\t";}
{	if($1 != null){
		contadornP[$1] = $2 + anterior;
		anterior = contadornP[$1];
		total = total + $2;
	}
}
END {
	for (valor in contadornP) {
		print valor "\t" contadornP[valor]/total;
	}
}' salida.txt | sort -n > time_udp_destECDF.txt

gnuplot << EOF
set title "Tiempo entre llegadas de paquetes UDP (Nivel 3). Puerto UDP Dest = 4939"
set xlabel "Tiempo entre llegadas (segundos)"
set logscale x 
set ylabel "Probabilidad"
unset label
unset key
set term png
set output "./plots/interarrivaltime_udp_dest.png"
plot "time_udp_destECDF.txt" using 1:2 with steps
EOF

echo -e "\n\tECDF generado!"


######APARTADO 8 (Ancho de Banda en bps)
#pruebo a cambiar dir mac 00:11:88:CC:33:F8

echo -e "\n##### APARTADO 8: Ancho de Banda (bps) #####\n"

echo -e "\n\t*Generando grafica de Ancho de Banda. Direccion MAC =  00:11:88:CC:33:F8"

awk 'BEGIN{ FS = "\t";}
{	if($10 == "00:11:88:cc:33:f8"){
		contadornP[int($13)] = contadornP[int($13)] + $1 * 8;
	}
}
END {
	for (valor in contadornP) {
		printf "%f\t%f\n", valor, contadornP[valor];
	}
}' datos.txt | sort -n > throughput_source.txt



awk 'BEGIN{ FS = "\t";}
{	if($11 == "00:11:88:cc:33:f8"){
		contadornP[int($13)] = contadornP[int($13)] + $1 * 8;
	}
}
END {
	for (valor in contadornP) {
		printf "%f\t%f\n", valor, contadornP[valor];
	}
}' datos.txt | sort -n > throughput_dest.txt


gnuplot << EOF
set title "Ancho de Banda. Dir MAC Dest = 00:11:88:CC:33:F8"
set xlabel "Tiempo (segundos)"
set ylabel "Ancho de Banda(Bits per second)"
unset label
unset key
set term png
set output "./plots/throughput.png"
plot "throughput_dest.txt" using 1:2 title 'Dest' with lines, "throughput_source.txt" using 1:2 title 'Source' with lines
EOF

echo -e "\n\tGrafica generada!";

rm crearCDF
#rm *.txt

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

#aqui podemos poner un if to guapo.

tshark -r trazap3.pcap -T fields -e frame.len -e eth.type -e vlan.etype -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e udp.srcport -e udp.dstport -e eth.src -e eth.dst -e ip.len -e frame.time_relative -e ip.proto > datos.txt 

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
#-r reverse (orden inverso)
#-k? k de Kampo(o Kolumna), y el numero de la que quieras
# Gracias pero lo busque hahahhahahah


#Direcciones IP dest nP = numero paquetes
#					 nB = numero bytes
  
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



#ECDF de tamaño paquetes a nivel 2. MAC Source.
#Filtro MAC = 00:11:88:CC:33:F8.

echo -e "\n\t*Generando ECDF de tamaño de paquetes a nivel 2. MAC Source.\n\t\tFiltro MAC = 00:11:88:CC:33:F8"
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

set title "ECDF tamanio paquetes a nivel 2 con MAC Source = 00:11:88:CC:33:F8"
set xlabel "Tamaño paquetes (bytes)"
set ylabel "Probabilidad (tanto por uno)"
set term jpeg
set output "/graficas/tamanio_mac_source.jpeg"
plot "eth_mac_sourceECDF.txt" using 1:2 with steps title "ECDF"
quit


echo -e "\n\t*ECDF generado"

#ECDF de tamaño paquetes a nivel 2. MAC Dest.
#Filtro MAC = 00:11:88:CC:33:F8.

echo -e "\n\t*Generando ECDF de tamaño de paquetes a nivel 2. MAC Dest.\n\t\tFiltro MAC = 00:11:88:CC:33:F8"
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


echo -e "\n\t*ECDF generado"


#ECDF de tamaño paquetes HTTP a nivel 3. TCP Source.
#Filtro TCP = 80.

echo -e "\n\t*Generando ECDF de tamaño paquetes HTTP a nivel 3. TCP Source.\n\t\tFiltro TCP = 80"
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


echo -e "\n\t*ECDF generado"


#ECDF de tamaño paquetes HTTP a nivel 3. TCP Dest.
#Filtro TCP = 80.

echo -e "\n\t*Generando ECDF de tamaño paquetes HTTP a nivel 3. TCP Dest.\n\t\tFiltro TCP = 80"
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


echo -e "\n\t*ECDF generado"


#ECDF de tamaño paquetes DNS nivel 3. UDP Source.
#Filtro UDP = 53.

echo -e "\n\t*Generando ECDF de tamaño paquetes DNS a nivel 3. UDP Source.\n\t\tFiltro UDP = 53"
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


echo -e "\n\t*ECDF generado"


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


echo -e "\n\t*ECDF generado"

# ESTO NO LO TENGO MUY CLARO. puntos 6 y 7. creo que cuando me aclare sera rapido. LO PREGUNTO MAÑANA. (CREO QUE LOS DATOS DE LA PCAP ESTAN MAL)


#ECDF de tiempo entre llegadas de paquetes TCP a nivel 3. IP Source.
#Filtro IP = 71.166.7.216. Protocolo TCP/IP = 0x06

echo -e "\n\t*Generando ECDF de tiempo entre llegadas de paquetes TCP a nivel 3. IP Source.\n\t\tFiltro IP = 71.166.7.216. Protocolo TCP/IP = 0x06"
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


echo -e "\n\t*ECDF generado"


#ECDF de tiempo entre llegadas de paquetes TCP a nivel 3. IP Dest.
#Filtro IP = 71.166.7.216. Protocolo TCP/IP = 0x06

echo -e "\n\t*Generando ECDF de tiempo entre llegadas de paquetes TCP a nivel 3. IP Dest.\n\t\tFiltro IP = 71.166.7.216. Protocolo TCP/IP = 0x06"

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


echo -e "\n\t*ECDF generado"

#ECDF de tiempo entre llegadas de paquetes UDP a nivel 3. UDP Source.
#Filtro UDP = 4939

echo -e "\n\t*Generando ECDF de tiempo entre llegadas de paquetes UDP a nivel 3. UDP Source.\n\t\tFiltro UDP = 4939"

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


echo -e "\n\t*ECDF generado"


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


echo -e "\n\t*ECDF generado"


rm datos.txt
rm aux.txt





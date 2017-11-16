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
#Creacion del directorio de las graficas
mkdir -p plots

#if ! [ -a datos.dat ]
#then
	tshark -r trazap3.pcap -T fields -e frame.len -e eth.type -e vlan.etype -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e udp.srcport -e udp.dstport -e eth.src -e eth.dst -e ip.len -e frame.time_relative -e ip.proto > datos.dat
#fi

######APARTADO 1 (PORCENTAJE DE PAQUETES IP)
echo -e "##### APARTADO 1: PORCENTAJE DE PAQUETES IP #####\n"
bash porcentajes.sh "datos.dat"


######APARTADO 2 (TOP 10 IP/PUERTOS-ORIGEN/DESTINO-BYTES/PAQUETES)
echo -e "\n##### APARTADO 2: TOPs 10 #####"

bash top10.sh "datos.dat" "1" "4" "Direcciones IP Source"

#Direcciones IP dest 
  
bash top10.sh "datos.dat" "1" "5" "Direcciones IP Dest"

#Puertos TCP Source

bash top10.sh "datos.dat" "1" "6" "Puertos TCP Source"

#Puertos TCP Dest

bash top10.sh "datos.dat" "1" "7" "Puertos TCP Dest"

#Puertos UDP Source

bash top10.sh "datos.dat" "1" "8" "Puertos UDP Source"

#Puertos UDP Dest

bash top10.sh "datos.dat" "1" "9" "Puertos UDP Dest"


######APARTADO 3 (ECDF Tamanos a nivel 2)
echo -e "\n##### APARTADO 3: ECDF Tamanos a nivel 2 #####\n"

#ECDF de tamaño paquetes a nivel 2. 
#Filtro MAC = 00:11:88:CC:33:F8.

echo -e "\t*Generando ECDF de tamaño de paquetes a nivel 2 (Tanto origen como destino).\n\t\tDireccion MAC empleada: 00:11:88:CC:33:F8"

bash ecdfdata.sh "datos.dat" "1" "eth_mac_sourceECDF.txt" "10" "00:11:88:cc:33:f8"

bash ecdfdata.sh "datos.dat" "1" "eth_mac_destECDF.txt" "11" "00:11:88:cc:33:f8"


gnuplot << EOF
set title "ECDF Tamano paquetes a nivel 2. MAC = 00:11:88:CC:33:F8"
set xlabel "Tamano paquetes (bytes)"
set ylabel "Probabilidad acumulada (P(x≤t))"
unset label
set term png
set output "./plots/tamanio_mac.png"
plot "eth_mac_destECDF.txt" using 1:2 title 'MAC = Dest' with steps, "eth_mac_sourceECDF.txt" using 1:2 title 'MAC = Source' with steps
EOF

echo -e "\n\tECDF generado!"

#ECDF de tamaño paquetes HTTP a nivel 3. TCP Source.
#Filtro TCP = 80.

echo -e "\n##### APARTADO 4: ECDF Tamanos de paquetes HTTP a nivel 3 #####\n"

echo -e "\t*Generando ECDF de tamaño paquetes HTTP a nivel 3. (Tanto Src como Dest)\n\t\tFiltro TCP = 80"

#Src
bash ecdfdata.sh "datos.dat" "12" "http_tcp_sourceECDF.txt" "6" "80"

#Dest
bash ecdfdata.sh "datos.dat" "12" "http_tcp_destECDF.txt" "7" "80"

#ECDF de tamaño paquetes HTTP a nivel 3. TCP Dest.
#Filtro TCP = 80.

#Plotting
gnuplot << EOF
set title "ECDF Tamano paquetes HTTP a nivel 3. TCP Port = 80"
set xlabel "Tamano paquetes (bytes)"
set ylabel "Probabilidad acumulada (P(x≤t))"
unset label
set term png
set output "./plots/tamanio_http.png"
plot "http_tcp_destECDF.txt" using 1:2 title 'TCP Port = Dest' with steps, "http_tcp_sourceECDF.txt" using 1:2 title 'TCP Port = Source' with steps
EOF

echo -e "\n\tECDF generado!"


echo -e "\n##### APARTADO 5: ECDF Tamanos de paquetes DNS a nivel 3 #####\n"
#ECDF de tamaño paquetes DNS nivel 3. UDP Source.
#Filtro UDP = 53.

echo -e "\t*Generando ECDF de tamaño paquetes DNS a nivel 3(Tanto Src como Dest).\n\t\tFiltro UDP = 53"

#Src
bash ecdfdata.sh "datos.dat" "12" "dns_udp_sourceECDF.txt" "8" "53"

#Dest
bash ecdfdata.sh "datos.dat" "12" "dns_udp_destECDF.txt" "9" "53"

#Plotting
gnuplot << EOF
set title "ECDF Tamano paquetes DNS a nivel 3. UDP Port = 53"
set xlabel "Tamano paquetes (bytes)"
set ylabel "Probabilidad acumulada (P(x≤t))"
unset label
set term png
set output "./plots/tamanio_dns.png"
plot "dns_udp_destECDF.txt" using 1:2 title 'UDP Port = Dest' with steps, "dns_udp_sourceECDF.txt" using 1:2 title 'UDP Port = Source' with steps
EOF

echo -e "\n\tECDF generado!"


echo -e "\n##### APARTADO 6: ECDF Interarrival Time de flujo TCP #####\n"

#ECDF de tiempo entre llegadas de paquetes TCP a nivel 3. 
#Filtro IP = 71.166.7.216. Protocolo TCP/IP = 0x06

echo -e "\t*Generando ECDF de tiempo entre llegadas de paquetes TCP a nivel 3(Tanto Src como Dest).\n\t\tFiltro IP = 71.166.7.216. Protocolo TCP/IP = 0x06"

#Src
bash ecdftimedata.sh "datos.dat" "13" "time_tcp_sourceECDF.txt" "4" "71.166.7.216" "14" "6"

#Dst
bash ecdftimedata.sh "datos.dat" "13" "time_tcp_destECDF.txt" "5" "71.166.7.216" "14" "6"

#Plotting
gnuplot << EOF
set title "Tiempo entre llegadas de paquetes TCP (Nivel 3). IP Dir = 71.166.7.216"
set xlabel "Tiempo entre llegadas (segundos)"
set logscale x
set ylabel "Probabilidad acumulada (P(x≤t))"
unset label
set term png
set output "./plots/interarrivaltime_tcp.png"
plot "time_tcp_destECDF.txt" using 1:2 title 'IP Dest = IP Dir' with steps, "time_tcp_sourceECDF.txt" using 1:2 title 'IP Source = IP Dir' with steps
EOF

echo -e "\n\tECDF generado!"


echo -e "\n##### APARTADO 7: ECDF Interarrival Time de flujo UDP #####\n"
#ECDF de tiempo entre llegadas de paquetes UDP a nivel 3.
#Filtro UDP = 4939


echo -e "\t*Generando ECDF de tiempo entre llegadas de paquetes UDP a nivel 3.(Tanto UDP Source como UDP Dest).\n\t\tFiltro UDP = 4939"

#Src
bash ecdftimedata.sh "datos.dat" "13" "time_udp_sourceECDF.txt" "8" "4939" "14" "17"
echo -e "\n\tAtencion, no hay ningun paquete que satisfaga el filtro. No se puede generar el ECDF de UDP Src."

#Dst
bash ecdftimedata.sh "datos.dat" "13" "time_udp_destECDF.txt" "9" "4939" "14" "17"

#Plotting
gnuplot << EOF
set title "Tiempo entre llegadas de paquetes UDP (Nivel 3)."
set xlabel "Tiempo entre llegadas (segundos)"
set logscale x 
set ylabel "Probabilidad acumulada (P(x≤t))"
unset label
set term png
set output "./plots/interarrivaltime_udp_dest.png"
plot "time_udp_destECDF.txt" using 1:2  title 'UDP Dest = 4939' with steps
EOF

echo -e "\n\tECDF generado!"


######APARTADO 8 (Ancho de Banda en bps)
#pruebo a cambiar dir mac 00:11:88:CC:33:F8

echo -e "\n##### APARTADO 8: Ancho de Banda (bps) #####\n"

echo -e "\n\t*Generando grafica de Ancho de Banda. Direccion MAC =  00:11:88:CC:33:F8"

bash throughput.sh "datos.dat" "13" "throughput_source.txt" "10" "00:11:88:cc:33:f8" "1"

bash throughput.sh "datos.dat" "13" "throughput_dest.txt" "11" "00:11:88:cc:33:f8" "1"


gnuplot << EOF
set title "Ancho de Banda. Dir MAC = 00:11:88:CC:33:F8"
set xlabel "Tiempo (segundos)"
set ylabel "Ancho de Banda(Bits per second)"
unset label
set term png
set output "./plots/throughput.png"
plot "throughput_dest.txt" using 1:2 title 'Eth Dest = Dir MAC' with lines, "throughput_source.txt" using 1:2 title 'Eth Source = Dir MAC' with lines
EOF

gnuplot << EOF
set title "Ancho de Banda. Dir MAC = 00:11:88:CC:33:F8"
set xlabel "Tiempo (segundos)"
set ylabel "Ancho de Banda(Bits per second)"
unset label
set term png
set output "./plots/throughputDestAmpliado.png"
plot "throughput_dest.txt" using 1:2 title 'Eth Dest = Dir MAC' with lines
EOF


echo -e "\n\tGrafica generada!";

rm crearCDF
rm *.txt

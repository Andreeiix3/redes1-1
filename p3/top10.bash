#Este script recibe los siguientes argumentos argumentos:
# $1: Fichero sobre el que se va a trabajar
# $2: Columna que indica la longitud de cada paquete
# $3: Columna que tiene los datos a rankear (Direcciones IP, Puertos...)
# $4: Nombre del ranking. Unicamente util para formatear la salida por pantalla. 
#La salida de este script son dos rankings por ejecución. Se ordena el parámetro $1 primero por número de repeticiones
#y luego por número de bytes.



awk -v var=$3 -v len=$2 'BEGIN{ FS = "\t"; }
{
	if($var != null){
		#	nP = numero paquetes
		#	nB = numero bytes
		contadornP[$var] = contadornP[$var] + 1;
		contadornB[$var] = contadornB[$var] + $len;
	}
}
END {
	for (valor in contadornP) {
		print valor "\t" contadornP[valor] "\t" contadornB[valor];
	}
}' $1 > aux.txt

echo -e "\n\t*TOP 10 " $4 "(Orden: Numero de paquetes)\n"
echo -e "Formato:"
echo -e  $4"//Numero de Paquetes//Numero de bytes\n"  
sort -t$'\t' -n -r -k2  aux.txt| head -n 10
echo -e "\n\t*TOP 10 "$4" (Orden: Numero de bytes)\n"
echo -e "Formato:"
echo -e  $4"//Numero de Paquetes//Numero de bytes\n"  
sort -t$'\t' -n -r -k3  aux.txt| head -n 10

rm aux.txt

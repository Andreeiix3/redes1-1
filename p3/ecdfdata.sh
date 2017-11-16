# $1: Fichero de datos sobre el que se trabaja 
# $2: Columna con el campo en el EJE X del ECDF
# $3: Fichero de salida
# $4: Columna a comparar (igualdad) en un posible filtro
# $5: Elemento comparador en un posible filtro


awk -v field=$2 -v filtercol=$4 -v filtervalue=$5 'BEGIN{ FS = "\t";}
{	if($filtercol == filtervalue){
		contadornP[$field] = contadornP[$field] + 1;
	}
}
END {
	for (valor in contadornP) {
		print valor "\t" contadornP[valor];
	}
}' $1 > aux.txt


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
}' salida.txt | sort -n > $3

rm salida.txt


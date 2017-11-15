# $1: Fichero de datos sobre el que se trabaja 
# $2: Columna con el campo en el EJE X del ECDF
# $3: Fichero de salida
# $4: Columna a comparar (igualdad) en un posible filtro
# $5: Elemento comparador en un posible filtro
# $6: Columa a comparar (igualdad) en un segundo filtro
# $7: Elemento a comparar en un segundo filtro


awk -v field=$2 -v filtercol=$4 -v filtervalue=$5 -v filter2col=$6 -v filter2value=$7 'BEGIN{ FS = "\t";}
{	if($filtercol == filtervalue && $filter2col == filter2value){
		tiempo_actual = $field - tiempo_anterior;
		contadornP[tiempo_actual] = contadornP[tiempo_actual] + 1;
		tiempo_anterior = $field;
	}
}
END {
	for (valor in contadornP) {
		printf "%f\t%f\n", valor, contadornP[valor];
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


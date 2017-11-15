# $1: Fichero de datos sobre el que se trabaja 
# $2: Columna con el campo en el EJE X del ECDF
# $3: Fichero de salida
# $4: Columna a comparar (igualdad) en un posible filtro
# $5: Elemento comparador en un posible filtro
# $6: Longitud del paquete

awk -v field=$2 -v filtercol=$4 -v filtervalue=$5 -v lengthvalue=$6  'BEGIN{ FS = "\t";}
{	if($filtercol == filtervalue){
		contadornP[int($field)] = contadornP[int($field)] + $lengthvalue * 8;
	}
}
END {
	for (valor in contadornP) {
		printf "%f\t%f\n", valor, contadornP[valor];
	}
}' $1 | sort -n > $3



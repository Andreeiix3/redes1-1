/***************************************************************************
 practica4.c
 Inicio, funciones auxiliares y modulos de transmision implmentados y a implementar de la practica 4.
Compila con warning pues falta usar variables y modificar funciones
 
 Compila: make
 Autor: Jose Luis Garcia Dorado
 2014 EPS-UAM v2
***************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include "interface.h"
#include "practica4.h"

/***************************Variables globales utiles*************************************************/
pcap_t* descr, *descr2; //Descriptores de la interface de red
pcap_dumper_t * pdumper;//y salida a pcap
uint64_t cont=0;	//Contador numero de mensajes enviados
char interface[10];	//Interface donde transmitir por ejemplo "eth0"
uint16_t ID=1;		//Identificador IP


void handleSignal(int nsignal){
	printf("Control C pulsado (%"PRIu64")\n", cont);
	pcap_close(descr);
	exit(OK);
}

int main(int argc, char **argv){	

	char errbuf[PCAP_ERRBUF_SIZE];
	char fichero_pcap_destino[CADENAS];
	uint8_t IP_destino_red[IP_ALEN];
	uint16_t MTU;
	uint16_t datalink;
	uint16_t puerto_destino;
	char data[IP_DATAGRAM_MAX];
	uint16_t pila_protocolos[CADENAS];
	FILE * f = NULL;

	int long_index=0;
	char opt;
	char flag_iface = 0, flag_ip = 0, flag_port = 0, flag_file = 0;

	static struct option options[] = {
		{"if",required_argument,0,'1'},
		{"ip",required_argument,0,'2'},
		{"pd",required_argument,0,'3'},
		{"f",required_argument,0,'4'},
		{"h",no_argument,0,'5'},
		{0,0,0,0}
	};

		//Dos opciones: leer de stdin o de fichero, adicionalmente para pruebas si no se introduce argumento se considera que el mensaje es "Payload "
	while ((opt = getopt_long_only(argc, argv,"1:2:3:4:5", options, &long_index )) != -1) {
		switch (opt) {

			case '1' :

				flag_iface = 1;
					//Por comodidad definimos interface como una variable global
				sprintf(interface,"%s",optarg);
				break;

			case '2' : 

				flag_ip = 1;
					//Leemos la IP a donde transmitir y la almacenamos en orden de red
				if (sscanf(optarg,"%"SCNu8".%"SCNu8".%"SCNu8".%"SCNu8"",
				                   &(IP_destino_red[0]),&(IP_destino_red[1]),&(IP_destino_red[2]),&(IP_destino_red[3])) != IP_ALEN){
					printf("Error: Fallo en la lectura IP destino %s\n", optarg);
					exit(ERROR);
				}

				break;

			case '3' :

				flag_port = 1;
					//Leemos el puerto a donde transmitir y la almacenamos en orden de hardware
				puerto_destino=atoi(optarg);
				break;

			case '4' :

				if(strcmp(optarg,"stdin")==0) {
					if (fgets(data, sizeof data, stdin)==NULL) {
						  	printf("Error leyendo desde stdin: %s %s %d.\n",errbuf,__FILE__,__LINE__);
						return ERROR;
					}
					sprintf(fichero_pcap_destino,"%s%s","stdin",".pcap");
				} else {
					sprintf(fichero_pcap_destino,"%s%s",optarg,".pcap");
					f = fopen(optarg, "r");
					if (fgets(data, sizeof data, f)==NULL) {
						  	printf("Error leyendo desde fichero %s: %s %s %d.\n",optarg,errbuf,__FILE__,__LINE__);
						return ERROR;
					}
					fclose(f);
				}
				flag_file = 1;

				break;

			case '5' : printf("Ayuda. Ejecucion: %s -if interface -ip IP -pd Puerto <-f /ruta/fichero_a_transmitir o stdin>: %d\n",argv[0],argc); exit(ERROR);
				break;

			case '?' : printf("Error. Ejecucion: %s -if interface -ip IP -pd Puerto <-f /ruta/fichero_a_transmitir o stdin>: %d\n",argv[0],argc); exit(ERROR);
				break;

			default: printf("Error. Ejecucion: %s -if interface -ip IP -pd Puerto <-f /ruta/fichero_a_transmitir o stdin>: %d\n",argv[0],argc); exit(ERROR);
				break;
        }
    }

	if ((flag_iface == 0) || (flag_ip == 0) || (flag_port == 0)){
		printf("Error. Ejecucion: %s -if interface -ip IP -pd Puerto <-f /ruta/fichero_a_transmitir o stdin>: %d\n",argv[0],argc);
		exit(ERROR);
	} else {
		printf("Interface:\n\t%s\n",interface);
		printf("IP:\n\t%"PRIu8".%"PRIu8".%"PRIu8".%"PRIu8"\n",IP_destino_red[0],IP_destino_red[1],IP_destino_red[2],IP_destino_red[3]);
		printf("Puerto destino:\n\t%"PRIu16"\n",puerto_destino);
	}

	if (flag_file == 0) {
		sprintf(data,"%s","Payload "); //Deben ser pares!
		sprintf(fichero_pcap_destino,"%s%s","debugging",".pcap");
	}

	if(signal(SIGINT,handleSignal)==SIG_ERR){
		printf("Error: Fallo al capturar la senal SIGINT.\n");
		return ERROR;
	}
	
	//Inicializamos las tablas de protocolos
	if(inicializarPilaEnviar()==ERROR){
      	printf("Error leyendo desde stdin: %s %s %d.\n",errbuf,__FILE__,__LINE__);
		return ERROR;
	}
	
	//Leemos el tamano maximo de transmision del nivel de enlace
	if(obtenerMTUInterface(interface, &MTU)==ERROR)
		return ERROR;
	
	printf("\n");
	//Descriptor de la interface de red donde inyectar trafico
	if ((descr = pcap_open_live(interface,MTU+ETH_HLEN,0, 0, errbuf)) == NULL){
		printf("Error: pcap_open_live(): %s %s %d.\n",errbuf,__FILE__,__LINE__);
		return ERROR;
	}

	datalink=(uint16_t)pcap_datalink(descr); //DLT_EN10MB==Ethernet

	//Descriptor del fichero de salida pcap para debugging
	descr2=pcap_open_dead(datalink,MTU+ETH_HLEN);
	pdumper=pcap_dump_open(descr2,fichero_pcap_destino);


	/**************PARTE 1*********/


	//Formamos y enviamos el trafico, debe enviarse un unico segmento por llamada a enviar() aunque luego se traduzca en mas de un datagrama
	//Primero un paquete UDP
	//Definimos la pila de protocolos que queremos seguir
	pila_protocolos[0]=UDP_PROTO; 
	pila_protocolos[1]=IP_PROTO; 
	pila_protocolos[2]=ETH_PROTO;
	
	//Rellenamos los parametros necesario para enviar el paquete a su destinatario y proceso
	Parametros parametros_udp; 
	memcpy(parametros_udp.IP_destino,IP_destino_red,IP_ALEN); 
	parametros_udp.puerto_destino=puerto_destino;
	
	//Enviamos los datos en data, que es lo que habiamos pasado como argumento
	if(enviar((uint8_t*)data,strlen(data),pila_protocolos,&parametros_udp)==ERROR ){
		printf("Error: enviar(): %s %s %d.\n",errbuf,__FILE__,__LINE__);
		return ERROR;
	}
	else cont++;

	printf("Enviado mensaje %"PRIu64", UDP almacenado en %s\n\n\n", cont,fichero_pcap_destino);

	
	/**************PARTE 2*********/

	//Luego, un paquete ICMP en concreto un ping
	pila_protocolos[0]=ICMP_PROTO;
	pila_protocolos[1]=IP_PROTO; 
	pila_protocolos[2]=ETH_PROTO;
	
	Parametros parametros_icmp; 
	parametros_icmp.tipo=PING_TIPO; 
	parametros_icmp.codigo=PING_CODE; 
	
	// Los datos en el ICMP no son relevantes, se prueba con esta cadena
	memcpy(parametros_icmp.IP_destino,IP_destino_red,IP_ALEN);
	if(enviar((uint8_t*)"Probando a hacer un ping",strlen("Probando a hacer un ping"),pila_protocolos,&parametros_icmp)==ERROR ){
		printf("Error: enviar(): %s %s %d.\n",errbuf,__FILE__,__LINE__);
		return ERROR;
	}
	else cont++;


	printf("Enviado mensaje %"PRIu64", ICMP almacenado en %s\n\n", cont,fichero_pcap_destino);

	//Cerramos descriptores
	pcap_close(descr);
	pcap_dump_close(pdumper);
	pcap_close(descr2);
	return OK;
}


/****************************************************************************************
* Nombre: enviar 									*
* Descripcion: Esta funcion envia un mensaje						*
* Argumentos: 										*
*  -mensaje: mensaje a enviar								*
*  -pila_protocolos: conjunto de protocolos a seguir					*
*  -longitud: bytes que componen mensaje						*
*  -parametros: parametros necesario para el envio (struct parametros)			*
* Retorno: OK/ERROR									*
****************************************************************************************/

uint8_t enviar(uint8_t* mensaje, uint64_t longitud,uint16_t* pila_protocolos,void *parametros){
	
	uint16_t protocolo=pila_protocolos[0];
	printf("Enviar(%"PRIu16") %s %d.\n",protocolo,__FILE__,__LINE__);
	
	if(protocolos_registrados[protocolo]==NULL){
		printf("Protocolo %"PRIu16" desconocido\n",protocolo);
		return ERROR;
	}
	else {
		return protocolos_registrados[protocolo](mensaje,longitud,pila_protocolos,parametros);
	}
	
	return ERROR;
}


/***************************TODO Pila de protocolos a implementar************************************/

/****************************************************************************************
* Nombre: moduloUDP 									*
* Descripcion: Esta funcion implementa el modulo de envio UDP				*
* Argumentos: 										*
*  -mensaje: mensaje a enviar								*
*  -pila_protocolos: conjunto de protocolos a seguir					*
*  -longitud: bytes que componen mensaje						*
*  -parametros: parametros necesario para el envio este protocolo			*
* Retorno: OK/ERROR									*
****************************************************************************************/

uint8_t moduloUDP(uint8_t* mensaje,uint64_t longitud, uint16_t* pila_protocolos,void *parametros){
	uint8_t segmento[UDP_SEG_MAX]={0};
	uint16_t puerto_origen = 0, suma_control=0;
	uint16_t aux16;
	uint32_t pos=0;
	uint16_t protocolo_inferior=pila_protocolos[1];
	printf("modulo UDP(%"PRIu16") %s %d.\n",protocolo_inferior,__FILE__,__LINE__);

	/*El campo longitud en UDP tiene 16 bits e indica el tamaño en bytes*/
	if (longitud>(pow(2,16)-UDP_HLEN)){
		printf("Error: mensaje demasiado grande para UDP (%f).\n",(pow(2,16)-UDP_HLEN));
		return ERROR;
	}

	Parametros udpdatos=*((Parametros*)parametros);
	uint16_t puerto_destino=udpdatos.puerto_destino;
	
	if(obtenerPuertoOrigen(&puerto_origen) == ERROR){
		printf("Error: no se pudo obtener el puerto de origen UDP.\n");
		return ERROR;
	}

	aux16=htons(puerto_origen);
	memcpy(segmento+pos,&aux16,sizeof(uint16_t));
	pos+=sizeof(uint16_t);

	/*Copia puerto destino*/
	aux16 = htons(puerto_destino);
	memcpy(segmento+pos,&aux16,sizeof(uint16_t));
	pos+=sizeof(uint16_t);

	/*Copia longitud*/
	aux16 = htons(longitud+UDP_HLEN);
	memcpy(segmento+pos,&aux16,sizeof(uint16_t));
	pos+=sizeof(uint16_t);

	/*Copia Checksum (todo a 0)*/
	memcpy(segmento+pos,&suma_control,sizeof(uint16_t));
	pos+=sizeof(uint16_t);

	/*ESTO DE AQUI ABAJO ESTA TREMENDAMENTE MAL*/
	/*Copia de todo el segmento, el mensaje*/


	memcpy(segmento+pos, mensaje, longitud);
	/*No sumamos pos de nuevo porque ya se hace en la llamada a la siguiente funcion*/

	//Se llama al protocolo definido de nivel inferior a traves de los punteros registrados en la tabla de protocolos registrados
	return protocolos_registrados[protocolo_inferior](segmento,longitud+pos,pila_protocolos,parametros);
}


/****************************************************************************************
* Nombre: moduloIP 									*
* Descripcion: Esta funcion implementa el modulo de envio IP				*
* Argumentos: 										*
*  -segmento: segmento a enviar								*
*  -pila_protocolos: conjunto de protocolos a seguir					*
*  -longitud: bytes que componen el segmento						*
*  -parametros: parametros necesario para el envio este protocolo			*
* Retorno: OK/ERROR									*
****************************************************************************************/

uint8_t moduloIP(uint8_t* segmento, uint64_t longitud, uint16_t* pila_protocolos,void *parametros){
	uint8_t datagrama[IP_DATAGRAM_MAX]={0};
	uint32_t aux32;
	uint16_t aux16;
	uint16_t mtu;
	uint16_t long_frag;
	uint8_t aux8;
	uint8_t * auxIP;
	uint8_t* checksum;
	uint32_t pos=0,pos_control=0,pos_frag=0;
	uint8_t IP_origen[IP_ALEN];
	uint16_t protocolo_superior=pila_protocolos[0];
	uint16_t protocolo_inferior=pila_protocolos[2];
	pila_protocolos++;
	uint8_t mascara[IP_ALEN],IP_rango_origen[IP_ALEN],IP_rango_destino[IP_ALEN];
	Parametros ipdatos=*((Parametros*)parametros);
	uint8_t* IP_destino = ipdatos.IP_destino;
	uint8_t IP_tipo=ipdatos.tipo;
	int numpack;
	int i;
	uint8_t* gateWay;


	printf("modulo IP(%"PRIu16") %s %d.\n",protocolo_inferior,__FILE__,__LINE__);


	//Control de tamaño - Necesario oara saber si hay que fragmentar o no
	//Obtenemos la MTU: Vemos que da 1500, eso es que ya han sido descontados los 8 de cabecera Ethernet
	if(obtenerMTUInterface(interface, &mtu) == ERROR){
		return ERROR;
	}



	//Comprobamos si cabe en un paquete
	if(longitud > mtu - IP_HLEN){
		//Fragmentacion	
		printf("ERRROR SEGMENTACION AUN NO IMPLEMENTADA");
		
		numpack = (longitud + IP_HLEN)/mtu;
		for(i = 0; i <= numpack; i++){

			/*En la fragmentación la cabecera del nivel se repite cambiando ciertos campos*/

			/*version, 4 o 6, en nuestro caso siempre 4 = 0100 = 0x4, la concatenamos con ihl*/
			/*ihl: Longitud de la cabecera en palabras de 32 bits, en nuestro caso sera 6 = 0110 = 0x6*/
			// No se ni como se representa un byte en memoria, si es al derechas o al reves HULIO
			// htons no es necesario en este caso, creo
			/* Mismo que sin fragmentación*/
			aux8 = htons(0x46);
			memcpy(datagrama+pos,&aux8,sizeof(uint8_t));
			pos+=sizeof(uint8_t);

			/*Tipo*/
			/* Mismo que sin fragmentación*/
			aux8 = IP_tipo;
			memcpy(datagrama+pos,&aux8,sizeof(uint8_t));
			pos+=sizeof(uint8_t);

			/*Longitud total*/
			/*Será la longitud de este fragmento incluida su cabecera*/
			/*En el caso de Ethernet siempre es 1500 excepto el último fragmento*/
			/*dDependiendp de la longitud del framento*/
			if(i == numpack){
				long_frag = longitud - mtu*numpack + IP_HLEN;
			}else{
				long_frag = mtu;
			}
			memcpy(datagrama+pos,&long_frag,sizeof(uint16_t));
			pos+=sizeof(uint16_t);

			/*Identificador*/
			/*Aqui podemos hacer o no el htons. Será único*/
			// Aqui y en icmp atencion!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
			aux16 = htons(*(uint16_t *)cont);
			memcpy(datagrama+pos,&aux16,sizeof(uint16_t));
			pos+=sizeof(uint16_t);

			/*Flags y offset*/
			/*Para los fragmentos que no son el último los tres bits de offset serán 001 y para el último 010. El offset el número*/
			/*de bytes del fragmento sin la cabecera. Sirve para la reensamblación del paquete. Viene a ser el desplazamiento.*/
			aux16 = ((mtu - IP_HLEN) * i)/8;
			if(i == numpack){
				aux16 = 0x3000 | aux16;
			}else{
				aux16 = 0x2000 | aux16;
			}
			memcpy(datagrama+pos,&aux16,sizeof(uint16_t));
			pos+=sizeof(uint16_t);

			/*Tiempo de vida*/
			/* Mismo que sin fragmentación*/
			aux8 = 64;
			memcpy(datagrama+pos,&aux8,sizeof(uint8_t));
			pos+=sizeof(uint8_t);

			/*Protocolo(superior)*/
			/* Mismo que sin fragmentación*/
			aux8 = htons(protocolo_superior);
			memcpy(datagrama+pos,&aux8,sizeof(uint8_t));
			pos+=sizeof(uint8_t);

			/*Checksum (Primera interaccion: Se asigna todo a 0*/
			/* Mismo que sin fragmentación*/
			pos_control = pos;
			aux16 = 0;
			memcpy(datagrama+pos,&aux16,sizeof(uint16_t));
			pos+=sizeof(uint16_t);

			/*Direccion IP Origen*/
			//a esto se le tiene que pasar un array de uint8_t donde aux8!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
			auxIP = (uint8_t*) malloc (IP_ALEN*sizeof(uint8_t));
			if(obtenerIPInterface(interface, auxIP) == ERROR)
				return ERROR;
			//No hace falta hacer htons porque la funcion a te la devuelve en orden de red
			memcpy(datagrama+pos,auxIP,sizeof(uint32_t));
			pos+=sizeof(uint32_t);
			free(auxIP);
			/*Direccion IP Destino*/
			/* Mismo que sin fragmentación*/
			aux32 = htonl(*((uint32_t*) IP_destino));
			memcpy(datagrama+pos,&aux32,sizeof(uint32_t));
			pos+=sizeof(uint32_t);

			/*Opciones y relleno todo a 0*/
			/* Mismo que sin fragmentación*/
			aux32 = 0 ;
			memcpy(datagrama+pos,&aux32,sizeof(uint32_t));
			pos+=sizeof(uint32_t);


			/*Ahora si se podria calcular el check sum*/
			// se calcula checksum con longitud, no era algo de cabecera???????????????????????????????????????????????????????????????????????
			checksum = (uint8_t *) malloc (sizeof(uint16_t));
			if(calcularChecksum(long_frag, datagrama, checksum)==ERROR)
				return ERROR;
			//No es necesario hacer el htons aqui porque la fucion ya te la devuelve en orden de red
			memcpy(datagrama + pos_control,&checksum,sizeof(uint16_t));
			free(checksum);

			/*Fin de la cabecera*/
	
			/*Añadimos debajo de datagrama los máximos bytes posibles de segmento = 1476*/
			/*No es necesario hacer htons pues ya se había hehco antes*/
			pos_frag = (mtu - IP_HLEN) * i;
			memcpy(datagrama+pos, segmento + pos_frag, long_frag - IP_HLEN);
			pos = pos + long_frag - IP_HLEN;


			/*Esto de la máscara se puede poner código arriba para solo hacer una vez estas comprobaciones!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
			/*AQUI COMPROBAMOS LA MASCARA CREO, SI LA MASCARA DE IP DESTINO E IP ORIGEN ES LA MISMA, PODEMOS HACER
			ARP REQUEST, SI NO, ASIGNAMOS A ETH DESTINO EL VALOR DE GATEAWAY*/

			if(obtenerMascaraInterface(interface, mascara) == ERROR)
				return ERROR;

			if(aplicarMascara(IP_origen, mascara, IP_ALEN, IP_rango_origen) == ERROR)
				return ERROR;
			if(aplicarMascara(IP_destino, mascara, IP_ALEN, IP_rango_destino) == ERROR)
				return ERROR;

			if((IP_rango_origen[1] == IP_rango_destino[1]) && (IP_rango_origen[2] == IP_rango_destino[2]) && (IP_rango_origen[3] == IP_rango_destino[3]) && (IP_rango_origen[4] == IP_rango_destino[4])){
				/*ARP REQUEST*/
				printf("El destino está en la misma subred que el origen\n");
				if(ARPrequest(interface, ipdatos.IP_destino, ipdatos.ETH_destino)){
					return ERROR;
				}
			} else{
				printf("El destino NO está en la misma subred que el origen\n");
				gateWay = (uint8_t*) malloc (IP_ALEN*sizeof(uint8_t));
				if(obtenerGateway(interface, gateWay) == ERROR)
					return ERROR;

				if(ARPrequest(interface, gateWay, ipdatos.ETH_destino) == ERROR)
					return ERROR;
				
				free(gateWay);
			}

			if(i == numpack){
				return protocolos_registrados[protocolo_inferior](datagrama + pos,long_frag,pila_protocolos,parametros);
			}else{
				if(protocolos_registrados[protocolo_inferior](datagrama + pos,long_frag,pila_protocolos,parametros) == ERROR)
					return ERROR;

			}

		}

	}
	else{
		//Un solo paquete
		numpack = 1;

		/*Empezamos a copiar en segmento*/

		/*version, 4 o 6, en nuestro caso siempre 4 = 0100 = 0x4, la concatenamos con ihl*/
		/*ihl: Longitud de la cabecera en palabras de 32 bits, en nuestro caso sera 6 = 0110 = 0x6*/
		// No se ni como se representa un byte en memoria, si es al derechas o al reves HULIO
		// htons no es necesario en este caso, creo
		aux8 = htons(0x46);
		memcpy(datagrama+pos,&aux8,sizeof(uint8_t));
		pos+=sizeof(uint8_t);

		/*Tipo*/
		aux8 = IP_tipo;
		memcpy(datagrama+pos,&aux8,sizeof(uint8_t));
		pos+=sizeof(uint8_t);

		/*Longitud total*/
		/*Es necesario distinguir entre fragmentacion y no freagmentacion*/
		aux16 = htons(*(uint16_t *)longitud);
		memcpy(datagrama+pos,&aux16,sizeof(uint16_t));
		pos+=sizeof(uint16_t);

		/*Identificador*/
		/*Se le asigna a cada pareja origen-destino*, es una movida, se usa para fragmentacion*/

		// Aqui y en icmp atencion!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
		aux16 = htons(*(uint16_t *)cont);
		memcpy(datagrama+pos,&aux16,sizeof(uint16_t));
		pos+=sizeof(uint16_t);

		/*Flags  y POSICION, ambas para fragmentacion*/
		aux16 = 0;
		aux16 = 0x3000 | aux16;
		memcpy(datagrama+pos,&aux16,sizeof(uint16_t));
		pos+=sizeof(uint16_t);
		
		/*Tiempo de vida*/
		//Wikipedia dice que normalmente toma el valor de 64 o 128
		// esto creo que estaria bn ponerlo en hexadecimal, no sabemos si te lo esta escribiendo en 16 bits y luego dandole la vuelta!!!!!!!!!!
		aux8 = 64;
		memcpy(datagrama+pos,&aux8,sizeof(uint8_t));
		pos+=sizeof(uint8_t);

		/*Protocolo(superior)*/ 
		aux8 = htons(protocolo_superior);
		memcpy(datagrama+pos,&aux8,sizeof(uint8_t));
		pos+=sizeof(uint8_t);

		/*Checksum (Primera interaccion: Se asigna todo a 0*/
		pos_control = pos;
		aux16 = 0;
		memcpy(datagrama+pos,&aux16,sizeof(uint16_t));
		pos+=sizeof(uint16_t);

		/*Direccion IP Origen*/
		//a esto se le tiene que pasar un array de uint8_t donde aux8!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
		auxIP = (uint8_t*) malloc (IP_ALEN*sizeof(uint8_t));
		if(obtenerIPInterface(interface, auxIP) == ERROR)
			return ERROR;
		//No hace falta hacer htons porque la funcion a te la devuelve en orden de red
		memcpy(datagrama+pos,auxIP,sizeof(uint32_t));
		pos+=sizeof(uint32_t);
		free(auxIP);
		
		/*Direccion IP Destino*/
		aux32 = htonl(*((uint32_t*) IP_destino));
		memcpy(datagrama+pos,&aux32,sizeof(uint32_t));
		pos+=sizeof(uint32_t);

		/*Opciones y relleno todo a 0*/
		aux32 = 0 ;
		memcpy(datagrama+pos,&aux32,sizeof(uint32_t));
		pos+=sizeof(uint32_t);

		/*Ahora si se podria calcular el check sum*/
		// se calcula checksum con longitud, no era algo de cabecera???????????????????????????????????????????????????????????????????????
		checksum = (uint8_t *) malloc (sizeof(uint16_t));
		if(calcularChecksum(longitud + pos, datagrama, checksum)==ERROR)
			return ERROR;
		//No es necesario hacer el htons aqui porque la fucion ya te la devuelve en orden de red
		memcpy(datagrama + pos_control,&checksum,sizeof(uint16_t));
		free(checksum);

		/*Fin de la cabecera*/
		
		/*Añadimos debajo de datagrama todo lo que había en segmento*/
		/*No es necesario hacer htons pues ya se había hehco antes*/
		memcpy(datagrama+pos, segmento, longitud);

		/*AQUI COMPROBAMOS LA MASCARA CREO, SI LA MASCARA DE IP DESTINO E IP ORIGEN ES LA MISMA, PODEMOS HACER
		ARP REQUEST, SI NO, ASIGNAMOS A ETH DESTINO EL VALOR DE GATEAWAY*/

		if(obtenerMascaraInterface(interface, mascara) == ERROR)
			return ERROR;

		if(aplicarMascara(IP_origen, mascara, IP_ALEN, IP_rango_origen) == ERROR)
			return ERROR;
		if(aplicarMascara(IP_destino, mascara, IP_ALEN, IP_rango_destino) == ERROR)
			return ERROR;

		if((IP_rango_origen[1] == IP_rango_destino[1]) && (IP_rango_origen[2] == IP_rango_destino[2]) && (IP_rango_origen[3] == IP_rango_destino[3]) && (IP_rango_origen[4] == IP_rango_destino[4])){
			/*ARP REQUEST*/
			printf("El destino está en la misma subred que el origen\n");
			if(ARPrequest(interface, ipdatos.IP_destino, ipdatos.ETH_destino)){
				return ERROR;
			}
		} else{
			printf("El destino NO está en la misma subred que el origen\n");
			gateWay = (uint8_t*) malloc (IP_ALEN*sizeof(uint8_t));
			if(obtenerGateway(interface, gateWay) == ERROR)
				return ERROR;

			if(ARPrequest(interface, gateWay, ipdatos.ETH_destino) == ERROR)
				return ERROR;
			
			free(gateWay);
		}
		return protocolos_registrados[protocolo_inferior](datagrama,longitud+pos,pila_protocolos,parametros);
	}


	/*Si llega aqui algo esta muuuuuuy mal*/
	printf("Si llega aqui algo esta muuuuuuy mal\n");
	return ERROR;
	
}


/****************************************************************************************
* Nombre: moduloETH 									*
* Descripcion: Esta funcion implementa el modulo de envio Ethernet			*
* Argumentos: 										*
*  -datagrama: datagrama a enviar							*
*  -pila_protocolos: conjunto de protocolos a seguir					*
*  -longitud: bytes que componen el datagrama						*
*  -parametros: Parametros necesario para el envio este protocolo			*
* Retorno: OK/ERROR									*
****************************************************************************************/

uint8_t moduloETH(uint8_t* datagrama, uint64_t longitud, uint16_t* pila_protocolos,void *parametros){
	
	uint8_t trama[ETH_FRAME_MAX]={0};
	uint8_t pos = 0;
	uint16_t aux16;
	uint16_t protocolo_superior=pila_protocolos[0];
	uint8_t* ETH_destino;
	uint8_t* ETH_origen;
	Parametros ethdatos =*((Parametros*)parametros);
    struct pcap_pkthdr cabecera;
    struct timeval time;

	pila_protocolos++;
	
	ETH_destino = ethdatos.ETH_destino;

	printf("modulo ETH(fisica) %s %d.\n",__FILE__,__LINE__);	


	if(obtenerMTUInterface(interface, &aux16) == ERROR)
		return ERROR;

	if(longitud + ETH_HLEN > aux16){
		printf("ERROR: moduloETH. MTU superada %s %d.\n",__FILE__,__LINE__);	
		return ERROR;
	}

	/*Direccion Ethernet Destino*/

	//Problema con los 48 buts de direccion mac, no son 64*/
	//No es necesario hacer htons porque el ARPRequest ya te lo da en formato de red
	
	memcpy(trama+pos,ETH_destino,ETH_ALEN*sizeof(uint8_t));
	pos+=ETH_ALEN*sizeof(uint8_t);


	/*Direccion Ethernet Origen*/
	//Tampoco hace falta htons
	ETH_origen = (uint8_t*) malloc (ETH_ALEN*sizeof(uint8_t));
	if(obtenerMACdeInterface(interface, ETH_origen)==ERROR){
		return ERROR;
	}
	memcpy(trama+pos,&ETH_origen,ETH_ALEN*sizeof(uint8_t));
	free(ETH_origen);
	pos+=ETH_ALEN*sizeof(uint8_t);

	/*Tipo Ethernet, IP es siempre 0x800*/

	aux16 = htons(IP_PROTO);
	memcpy(trama+pos,&aux16,sizeof(uint16_t));
	pos+=sizeof(uint16_t);

	//Copiamos el datagrama "debajo de la trama"
	memcpy(trama+pos, datagrama, longitud*sizeof(uint8_t));

	pcap_sendpacket(descr, (const u_char *) trama, (longitud + pos)*sizeof(uint8_t));
	

	time.tv_sec = 5;
	cabecera.ts = time;
	cabecera.caplen = longitud + pos;
	cabecera.len = longitud + pos;
	pcap_dump((uint8_t *) pdumper, &cabecera,  trama);

	printf("\n\n\nEsta es una impresion de comprobacion:\n");
	mostrarPaquete(trama, longitud + pos);

	return OK;
}


/****************************************************************************************
* Nombre: moduloICMP 									*
* Descripcion: Esta funcion implementa el modulo de envio ICMP				*
* Argumentos: 										*
*  -mensaje: mensaje a anadir a la cabecera ICMP					*
*  -pila_protocolos: conjunto de protocolos a seguir					*
*  -longitud: bytes que componen el mensaje						*
*  -parametros: parametros necesario para el envio este protocolo			*
* Retorno: OK/ERROR									*
****************************************************************************************/

uint8_t moduloICMP(uint8_t* mensaje,uint64_t longitud, uint16_t* pila_protocolos,void *parametros){
	uint8_t segmento[ICMP_DATAGRAM_MAX]={0};
	uint16_t suma_control=0, identificador, numsecuencia;
	uint16_t aux16;
	uint32_t pos=0;
	uint16_t protocolo_inferior=pila_protocolos[1];
	uint8_t * mensajeaux;
	printf("modulo UDP(%"PRIu16") %s %d.\n",protocolo_inferior,__FILE__,__LINE__);


	// ESTO POSIBLEMENTE SE DEBA COPROBAR QUE EL DATAGRAMA NO MIDA MAS DE 48
	/*El campo longitud en UDP tiene 16 bits e indica el tamaño en bytes*/
	if (longitud>(ICMP_DATAGRAM_MAX-ICMP_HLEN)){
		printf("Error: mensaje demasiado grande para UDP (%d).\n",(ICMP_DATAGRAM_MAX-ICMP_HLEN));
		return ERROR;
	}

	Parametros icmpparametros = *(Parametros *) parametros;

	/* El campo tipo será 8, el codigo 0 (enunciado) y a identificador y numsecuencia les asignaremos el contador */
	
	identificador = cont;
	numsecuencia = cont;
	
	/*if(obtenerPuertoOrigen(&puerto_origen) == ERROR){
		printf("Error: no se pudo obtener el puerto de origen UDP.\n");
		return ERROR;
	}*/

	/*Copia tipo*/
	memcpy(segmento+pos,&icmpparametros.tipo,sizeof(uint8_t));
	pos+=sizeof(uint8_t);

	/*Copia codigo*/
	memcpy(segmento+pos,&icmpparametros.codigo,sizeof(uint8_t));
	pos+=sizeof(uint8_t);

	/*Guardamos dirección para calcular el cheksum posteriormente */
	mensajeaux = segmento + pos;
	/*Copia Checksum (todo a 0)*/
	memcpy(segmento+pos,&suma_control,sizeof(uint16_t));
	pos+=sizeof(uint16_t);

	/*Copia identificador*/
	aux16 = htons(identificador);
	memcpy(segmento+pos,&aux16,sizeof(uint16_t));
	pos+=sizeof(uint16_t);

	/*Copia numsecuencia*/
	aux16 = htons(numsecuencia);
	memcpy(segmento+pos,&aux16,sizeof(uint16_t));
	pos+=sizeof(uint16_t);

	/*Copia de todo el segmento, el mensaje*/
	memcpy(segmento+pos, mensaje, longitud * sizeof(uint8_t));
	/*Calculamos el checksum del datagrama ICMP*/
	if(calcularChecksum(longitud+pos, mensaje, mensajeaux) == ERROR)
		return ERROR;

	//Se llama al protocolo definido de nivel inferior a traves de los punteros registrados en la tabla de protocolos registrados
	return protocolos_registrados[protocolo_inferior](segmento,longitud+pos,pila_protocolos,parametros);


//TODO
//[....]

}


/***************************Funciones auxiliares a implementar***********************************/

/****************************************************************************************
* Nombre: aplicarMascara 								*
* Descripcion: Esta funcion aplica una mascara a una vector				*
* Argumentos: 										*
*  -IP: IP a la que aplicar la mascara en orden de red					*
*  -mascara: mascara a aplicar en orden de red						*
*  -longitud: bytes que componen la direccion (IPv4 == 4)				*
*  -resultado: Resultados de aplicar mascara en IP en orden red				*
* Retorno: OK/ERROR									*
****************************************************************************************/

/*La reserva de memoria debe hacerse fuera de la funcion*/
uint8_t aplicarMascara(uint8_t* IP, uint8_t* mascara, uint32_t longitud, uint8_t* resultado){

	int i;

	if( IP == NULL || mascara == NULL){
		return ERROR;
	}

	for(i = 0; i<longitud; i++){
		resultado[i] = (IP[i] & mascara[i]);
	}

	return OK;
}


/***************************Funciones auxiliares implementadas**************************************/

/****************************************************************************************
* Nombre: mostrarPaquete 								*
* Descripcion: Esta funcion imprime por pantalla en hexadecimal un vector		*
* Argumentos: 										*
*  -paquete: bytes que conforman un paquete						*
*  -longitud: Bytes que componen el mensaje						*
* Retorno: OK/ERROR									*
****************************************************************************************/

uint8_t mostrarPaquete(uint8_t * paquete, uint32_t longitud){
	uint32_t i;
	printf("Paquete:\n");
	for (i=0;i<longitud;i++){
		printf("%02"PRIx8" ", paquete[i]);
	}
	printf("\n");
	return OK;
}


/****************************************************************************************
* Nombre: calcularChecksum							     	*
* Descripcion: Esta funcion devuelve el ckecksum tal como lo calcula IP/ICMP		*
* Argumentos:										*
*   -longitud: numero de bytes de los datos sobre los que calcular el checksum		*
*   -datos: datos sobre los que calcular el checksum					*
*   -checksum: checksum de los datos (2 bytes) en orden de red! 			*
* Retorno: OK/ERROR									*
****************************************************************************************/

uint8_t calcularChecksum(uint16_t longitud, uint8_t *datos, uint8_t *checksum) {
    uint16_t word16;
    uint32_t sum=0;
    int i;
    // make 16 bit words out of every two adjacent 8 bit words in the packet
    // and add them up
    for (i=0; i<longitud; i=i+2){
        word16 = (datos[i]<<8) + datos[i+1];
        sum += (uint32_t)word16;       
    }
    // take only 16 bits out of the 32 bit sum and add up the carries
    while (sum>>16) {
        sum = (sum & 0xFFFF)+(sum >> 16);
    }
    // one's complement the result
    sum = ~sum;      
    checksum[0] = sum >> 8;
    checksum[1] = sum & 0xFF;
    return OK;
}


/***************************Funciones inicializacion implementadas*********************************/

/****************************************************************************************
* Nombre: inicializarPilaEnviar     							*
* Descripcion: inicializar la pila de red para enviar registrando los distintos modulos *
* Retorno: OK/ERROR									*
****************************************************************************************/

uint8_t inicializarPilaEnviar() {
	bzero(protocolos_registrados,MAX_PROTOCOL*sizeof(pf_notificacion));
	if(registrarProtocolo(ETH_PROTO, moduloETH, protocolos_registrados)==ERROR)
		return ERROR;

	if(registrarProtocolo(IP_PROTO, moduloIP, protocolos_registrados)==ERROR)
		return ERROR;
	 
	if(registrarProtocolo(UDP_PROTO, moduloUDP, protocolos_registrados)==ERROR)
		return ERROR;
	
	if(registrarProtocolo(ICMP_PROTO, moduloICMP, protocolos_registrados)==ERROR)
		return ERROR;
	return OK;
}


/****************************************************************************************
* Nombre: registrarProtocolo 								*
* Descripcion: Registra un protocolo en la tabla de protocolos 				*
* Argumentos:										*
*  -protocolo: Referencia del protocolo (ver RFC 1700)					*
*  -handleModule: Funcion a llamar con los datos a enviar				*
*  -protocolos_registrados: vector de funciones registradas 				*
* Retorno: OK/ERROR 									*
*****************************************************************************************/

uint8_t registrarProtocolo(uint16_t protocolo, pf_notificacion handleModule, pf_notificacion* protocolos_registrados){
	if(protocolos_registrados==NULL ||  handleModule==NULL){		
		printf("Error: registrarProtocolo(): entradas nulas.\n");
		return ERROR;
	}
	else
		protocolos_registrados[protocolo]=handleModule;
	return OK;
}



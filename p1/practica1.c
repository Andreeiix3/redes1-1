
/***************************************************************************
practica1.c

 Dos funciones:

 1) Leer paquetes de una traza pasada como argumento
 2) Capturar paquetes de la red, modificar su fecha de captura en dos dias y
    guardarlos en un nuevo fichero traza (pcap).

 Ambas funcionalidades imprimen por pantalla los N primeros bits y el momento
 de captura de cada paquete y cuentan el numero total de paquetes analizados.

 Compila: make
 Autores: Emilio Cuesta y Pablo Alejo Polania
 2017 EPS-UAM
***************************************************************************/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>
#include <netinet/in.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <signal.h>
#include <time.h>
#include "practica1.h"

pcap_t *descr= NULL, *descr2=NULL;
pcap_dumper_t *pdumper = NULL;
int counter = 0;

/*Define el comportamiento ante la señal SIGINT (Ctrl+C)*/
void handle(int nsignal){
    printf("\nControl C pulsado\n");
    if(descr)
        pcap_close(descr);
    if(descr2)
        pcap_close(descr2);
    if(pdumper)
        pcap_dump_close(pdumper);
	printf("Se han leido %d paquetes\n", counter);
    exit(OK);
 }

int main(int argc, char **argv){

	int retorno=0, nbytes = 0, i, aux = 0;
    char errbuf[PCAP_ERRBUF_SIZE];
    uint8_t *paquete=NULL;
    struct pcap_pkthdr *cabecera=NULL;
    char file_name[256];
    struct timeval time;


    if(argc <= 1 || argc > 3 ){
        printf("Error: Fallo en el numero de argumentos.\nEs obligatorio introducir un primer argumento y opcional un segundo argumento. Formato:\n int N: numero de bytes de cada paquete mostrados.\n traza.pcap: traza a analizar.\n");
		return ERROR;
	}

    if(signal(SIGINT,handle)==SIG_ERR){
        printf("Error: Fallo al capturar la senal SIGINT.\n");
        exit(ERROR);
    }

	nbytes = atoi(argv[1]);
	if(nbytes < 0){
		printf("El numero de bytes a capturar debe ser positivo.\n");
		return ERROR;
	}
	if(argc == 2){ /* Se pasa solo el numero de bytes a mostrar de cada paquete. Captura en vivo */

        //OJO!!!!!!!!!! pongo wlo1 porque en la resi estoy con wifi y no me va la mv. Hay que cmabiarlo a eth0
        //Apertura de interface
		descr = pcap_open_live("eth0",ETH_FRAME_MAX,0,100, errbuf);
		if (!descr){
		    printf("Error: pcap_open_live(): %s, %s %d.\n",errbuf,__FILE__,__LINE__);
		    exit(ERROR);
    	}

 		//Volcado de traza
		descr2 = pcap_open_dead(DLT_EN10MB,ETH_FRAME_MAX);
    	if (!descr){
		    printf("Error al abrir el dump.\n");
		    pcap_close(descr);
		    exit(ERROR);
    	}
		gettimeofday(&time,NULL);
    	sprintf(file_name,"eth0.%lld.pcap",(long long)time.tv_sec);
    	pdumper=pcap_dump_open(descr2,file_name);
    	if(!pdumper){
        	printf("Error al abrir el dumper: %s, %s %d.\n",pcap_geterr(descr),__FILE__,__LINE__);
        	pcap_close(descr);
            pcap_close(descr2);
    	}

	}
	else{ /*Trabaja sobre una traza pasada como argumento */

		strcpy(file_name, argv[2]);
		descr = pcap_open_offline(file_name, errbuf);
		if (!descr){
		    printf("Error: pcap_open_offline(): %s, %s %d.\n",errbuf,__FILE__,__LINE__);
		    exit(ERROR);
    	}

	}

    while (1){

        retorno = pcap_next_ex(descr,&cabecera,(const u_char **)&paquete);

        if(retorno == -1){      //En caso de error
            printf("Error al capturar un paquete %s, %s %d.\n",pcap_geterr(descr),__FILE__,__LINE__);
            pcap_close(descr);
            if(pdumper){
                pcap_close(descr2);
                pcap_dump_close(pdumper);
            }
            exit(ERROR);
        }
        else if(retorno == 0){
            continue;
        }
        else if(retorno==-2){
			printf("Se han leido todos los paquetes disponibles\n");
            break;
        }
        //En otro caso
        counter++;
        printf("Nuevo paquete capturado a las %s",ctime((const time_t*)&(cabecera->ts.tv_sec)));
        printf("Contenido:\n");
        if(nbytes < cabecera->caplen){
            aux = nbytes;
        }
        else{
            aux = cabecera->caplen;
        }
        for(i=0; i<aux; i++){
            printf("%02X ", paquete[i]);
        }
        printf("\n");
        if(pdumper){
			cabecera->ts.tv_sec = cabecera->ts.tv_sec + 2*SECONDS_PER_DAY;
            /*No es necesario modificar el campo cabecera->ts.tv_usec porque almacena valores de decimas, centisimas... de segundo.
              La conversion de dos dias es directa*/
			printf("Se ha modificado el instante de captura a %s\n",ctime((const time_t*)&(cabecera->ts.tv_sec)));
            pcap_dump((uint8_t *)pdumper,cabecera,paquete);
        }
    }

    pcap_close(descr);
	if(pdumper){
        pcap_close(descr2);
    	pcap_dump_close(pdumper);
	}
    return OK;
}

/***************************************************************************
 practica2.c
 Muestra una serie de campos (indicados en enunciado) de unas trazas pasadas como argumento.
 Estos campos pertenecen a las cabeceras Ethernet-IP-UDP/TCP

 Tambien deja de analizar paquetes de acuerdo a varios posibles filtros.

 Compila: gcc -Wall -o practica2 practica2.c -lpcap, make
 Autores originales: Jose Luis Garcia Dorado, Jorge E. Lopez de Vergara Mendez, Rafael Leira
 Codigo modificado por: Emilio Cuesta Fernandez, Pablo Alejo Polania Bernardez
 2017 EPS-UAM
***************************************************************************/

#include <stdio.h>
#include <stdlib.h>

#include <pcap.h>
#include <string.h>
#include <netinet/in.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <signal.h>
#include <time.h>
#include <getopt.h>
#include <inttypes.h>
#include "practica2.h"


/*Variables globales*/
pcap_t *descr = NULL;
uint64_t contador = 0;
uint8_t ipsrc_filter[IP_ALEN] = {NO_FILTER};
uint8_t ipdst_filter[IP_ALEN] = {NO_FILTER};
uint16_t sport_filter= NO_FILTER;
uint16_t dport_filter = NO_FILTER;

void handleSignal(int nsignal){

	(void) nsignal; // indicamos al compilador que no nos importa que nsignal no se utilice

	printf("Control C pulsado (%"PRIu64" paquetes leidos)\n", contador);
	pcap_close(descr);
	exit(OK);
}

int main(int argc, char **argv)
{
	uint8_t *pack = NULL;
	struct pcap_pkthdr *hdr;

	char errbuf[PCAP_ERRBUF_SIZE];
	char entrada[256];
	int long_index = 0, retorno = 0;
	char opt;
	char * token;
	int i;

	
	(void) errbuf; //indicamos al compilador que no nos importa que errbuf no se utilice. Esta linea debe ser eliminada en la entrega final.

	if (signal(SIGINT, handleSignal) == SIG_ERR) {
		printf("Error: Fallo al capturar la senal SIGINT.\n");
		exit(ERROR);
	}

	if (argc > 1) {
		if (strlen(argv[1]) < 256) {
			strcpy(entrada, argv[1]);
		}

	} else {
		printf("Ejecucion: %s <-f traza.pcap / -i eth0> [-ipo IPO] [-ipd IPD] [-po PO] [-pd PD]\n", argv[0]);
		exit(ERROR);
	}

	static struct option options[] = {
		{"f", required_argument, 0, 'f'},
		{"i",required_argument, 0,'i'},
		{"ipo", required_argument, 0, '1'},
		{"ipd", required_argument, 0, '2'},
		{"po", required_argument, 0, '3'},
		{"pd", required_argument, 0, '4'},
		{"h", no_argument, 0, '5'},
		{0, 0, 0, 0}
	};

	//Simple lectura por parametros por completar casos de error, ojo no cumple 100% los requisitos del enunciado!
	while ((opt = getopt_long_only(argc, argv, "f:i:1:2:3:4:5", options, &long_index)) != -1) {
		switch (opt) {
		case 'i' :
			if(descr) { // comprobamos que no se ha abierto ninguna otra interfaz o fichero
				printf("Ha seleccionado más de una fuente de datos\n");
				pcap_close(descr);
				exit(ERROR);
			}
			
			if ( (descr = pcap_open_live(optarg, SNAPLENGTH, 0, 100, errbuf)) == NULL){
				printf("Error: pcap_open_live(): Interface: %s, %s %s %d.\n", optarg,errbuf,__FILE__,__LINE__);
				exit(ERROR);
			}
			break;

		case 'f' :
			if(descr) { // comprobamos que no se ha abierto ninguna otra interfaz o fichero
				printf("Ha seleccionado más de una fuente de datos\n");
				pcap_close(descr);
				exit(ERROR);
			}

			if ((descr = pcap_open_offline(optarg, errbuf)) == NULL) {
				printf("Error: pcap_open_offline(): File: %s, %s %s %d.\n", optarg, errbuf, __FILE__, __LINE__);
				exit(ERROR);
			}

			break;

		case '1' :
			if (sscanf(optarg, "%"SCNu8".%"SCNu8".%"SCNu8".%"SCNu8"", &(ipsrc_filter[0]), &(ipsrc_filter[1]), &(ipsrc_filter[2]), &(ipsrc_filter[3])) != IP_ALEN) {
				printf("Error ipo_filtro. Ejecucion: %s /ruta/captura_pcap [-ipo IPO] [-ipd IPD] [-po PO] [-pd PD]: %d\n", argv[0], argc);
				exit(ERROR);
			}
			printf("Opción -ipo con valor: '%s'\n", optarg);
			token = strtok(optarg, ".");
			ipsrc_filter[0] = (uint8_t) atoi(token);
			i = 0;
			while(token != NULL){
				
				ipsrc_filter[i] = (uint8_t) atoi(token);
				token = strtok(NULL, ".");
				i++;
			}
			


			break;

		case '2' :
			if (sscanf(optarg, "%"SCNu8".%"SCNu8".%"SCNu8".%"SCNu8"", &(ipdst_filter[0]), &(ipdst_filter[1]), &(ipdst_filter[2]), &(ipdst_filter[3])) != IP_ALEN) {
				printf("Error ipd_filtro. Ejecucion: %s /ruta/captura_pcap [-ipo IPO] [-ipd IPD] [-po PO] [-pd PD]: %d\n", argv[0], argc);
				exit(ERROR);
			}
			printf("Opción -ipd con valor: '%s'\n", optarg);
			token = strtok(optarg, ".");
			ipdst_filter[0] = (uint8_t) atoi(token);
			i = 0;
			while(token != NULL){
				
				ipdst_filter[i] = (uint8_t) atoi(token);
				token = strtok(NULL, ".");
				i++;
			}

			break;

		case '3' :
			if ((sport_filter= atoi(optarg)) == 0) {
				printf("Error po_filtro.Ejecucion: %s /ruta/captura_pcap [-ipo IPO] [-ipd IPD] [-po PO] [-pd PD]: %d\n", argv[0], argc);
				exit(ERROR);
			}

			break;

		case '4' :
			if ((dport_filter = atoi(optarg)) == 0) {
				printf("Error pd_filtro. Ejecucion: %s /ruta/captura_pcap [-ipo IPO] [-ipd IPD] [-po PO] [-pd PD]: %d\n", argv[0], argc);
				exit(ERROR);
			}
			break;

		case '5' :
			printf("Ayuda. Ejecucion: %s <-f traza.pcap / -i eth0> [-ipo IPO] [-ipd IPD] [-po PO] [-pd PD]: %d\n", argv[0], argc);
			exit(ERROR);
			break;

		case '?' :
		default:
			printf("Error. Ejecucion: %s <-f traza.pcap / -i eth0> [-ipo IPO] [-ipd IPD] [-po PO] [-pd PD]: %d\n", argv[0], argc);
			exit(ERROR);
			break;
		}
	}

	if (!descr) {
		printf("No selecciono ningún origen de paquetes.\n");
		return ERROR;
	}

	//Simple comprobacion de la correcion de la lectura de parametros
	printf("Filtro:\n");
	if(ipsrc_filter[0]!=0){
		printf("ipsrc_filter:%"PRIu8".%"PRIu8".%"PRIu8".%"PRIu8"\t", ipsrc_filter[0], ipsrc_filter[1], ipsrc_filter[2], ipsrc_filter[3]);
	}
	if(ipdst_filter[0]!=0){
		printf("ipdst_filter:%"PRIu8".%"PRIu8".%"PRIu8".%"PRIu8"\t", ipdst_filter[0], ipdst_filter[1], ipdst_filter[2], ipdst_filter[3]);
	}

	if (sport_filter!= NO_FILTER) {
		printf("po_filtro=%"PRIu16"\t", sport_filter);
	}

	if (dport_filter != NO_FILTER) {
		printf("pd_filtro=%"PRIu16"\t", dport_filter);
	}

	printf("\n\n");

	do {
		retorno = pcap_next_ex(descr, &hdr, (const u_char **)&pack);

		if (retorno == PACK_READ) { //Todo correcto
			contador++;
			analizar_paquete(hdr, pack);
		
		} else if (retorno == PACK_ERR) { //En caso de error
			printf("Error al capturar un paquetes %s, %s %d.\n", pcap_geterr(descr), __FILE__, __LINE__);
			pcap_close(descr);
			exit(ERROR);

		}
	} while (retorno != TRACE_END);

	printf("\nSe procesaron %"PRIu64" paquetes.\n\n", contador);
	pcap_close(descr);
	return OK;
}



void analizar_paquete(const struct pcap_pkthdr *hdr, const uint8_t *pack)
{
	int i = 0;
	uint8_t ip_protocol;
	uint8_t ip_ihl;
	uint16_t ip_offset;
	const uint8_t * aux_pointer;
	uint16_t lvl4_ports;
	uint8_t tcp_syn;
	uint8_t tcp_ack;


	printf("\n********* PAQUETE NUMERO %ld *********\n", contador);
	printf("Paquete capturado el %s\n", ctime((const time_t *) & (hdr->ts.tv_sec)));

	
	/*Nivel 2*/
	printf("Imprimiendo campos del Nivel 2 (Ethernet):\n");

	/*Destino*/
	printf("\t*Direccion ETH destino: ");
	
	printf("%02X", pack[0]);

	for (i = 1; i < ETH_ALEN; i++) {
		printf(":%02X", pack[i]);
	}

	printf("\n");
	pack += ETH_ALEN;
	
	/*Origen*/
	printf("\t*Direccion ETH origen: ");
	
	/*Impresion del primer byte de la direccion*/
	printf("%02X", pack[0]);

	/*Impresion del resto de bytes de la direccion*/
	for (i = 1; i < ETH_ALEN; i++) {
		printf(":%02X", pack[i]);
	}

	printf("\n");
	
	pack+=ETH_ALEN;


	printf("\t*Tipo Ethernet: ");
	for (i = 0; i < ETH_TLEN; i++) {
		printf("%02X", pack[i]);		
	}

	if(pack[0] != 0x08|| pack[1] != 0x00 ){
		/*Esto indica que el siguiente protocolo no es IPv4*/
		printf("\nEl siguiente protocolo no es el esperado, no se imprimirá informacion correspondiente a los siguientes niveles\n\n");		
		return;
	}

	printf("\nImprimiendo campos del Nivel 3 (IP):\n");
	pack += ETH_TLEN; 

	/*Nivel 3*/
	aux_pointer = pack;

	printf("\t*Version IP: %u\n", pack[0]>>4);
	ip_ihl = (pack[0]&0x0F)*4;
	printf("\t*Longitud de cabecera: %u bytes\n", ip_ihl);

	pack += 2;

	printf("\t*Longitud total: %u\n", ntohs(*(uint16_t *) pack));

	pack += 4;

	ip_offset = ntohs((*(uint16_t *) pack))&0x1FFF;
	printf("\t*Posicion/Desplazamiento: %u\n", ip_offset);

	

	pack += 2;

	printf("\t*Tiempo de vida: %u\n", pack[0]);
	ip_protocol = pack[1];
	printf("\t*Protocolo:%u\n", ip_protocol);
	

	pack += 4;
	
	printf("\t*Direccion IP de origen: %u", pack[0]);

	/*Impresion del resto de bytes de la direccion*/
	for (i = 1; i < IP_ALEN; i++) {
		printf(".%u", pack[i]);
	}
	
	printf("\n");
	/* Filtrado de la dirección origen de IP */
	if(ipsrc_filter[0] != 0 || ipsrc_filter[1] != 0 || ipsrc_filter[2] != 0 || ipsrc_filter[3] != 0){
		if(ipsrc_filter[0] != pack[0] || ipsrc_filter[1] != pack[1] || ipsrc_filter[2] != pack[2] || ipsrc_filter[3] != pack[3]){
			printf("La dirección origen de IP de este paquete NO coincide con la del filtro: ");
			printf("%"PRIu8".%"PRIu8".%"PRIu8".%"PRIu8"\n", ipsrc_filter[0], ipsrc_filter[1], ipsrc_filter[2], ipsrc_filter[3]);
			printf("Se aborta la impresion de los siguientes campos.\n\n");
			return;
		}
	}

	pack += 4;

	printf("\t*Direccion IP de destino: %u", pack[0]);

	/*Impresion del resto de bytes de la direccion*/
	for (i = 1; i < IP_ALEN; i++) {
		printf(".%u", pack[i]);
	}
	
	printf("\n");
	/* Filtrado de la dirección destino de IP */
	if(ipdst_filter[0] != 0 || ipdst_filter[1] != 0 || ipdst_filter[2] != 0 || ipdst_filter[3] != 0){
		if(ipdst_filter[0] != pack[0] || ipdst_filter[1] != pack[1] || ipdst_filter[2] != pack[2] || ipdst_filter[3] != pack[3]){
			printf("La dirección destino de IP de este paquete NO coincide con la del filtro: ");
			printf("%"PRIu8".%"PRIu8".%"PRIu8".%"PRIu8"\n", ipdst_filter[0], ipdst_filter[1], ipdst_filter[2], ipdst_filter[3]);
			printf("Se aborta la impresion de los siguientes campos.\n\n");
			return;
		}
	}

	if(ip_offset != 0){
		printf("El desplazamiento es disinto de 0. Este paquete no contiene cabecera de nivel 4.\n");
	    printf("El paquete se ha analizado por completo.\n\n");
		return;
	} 



	/*IHL te dice el numero de palabras de 32 bits que tiene el nivel ip. Hay que multiplicar por 4
	para convertir a bytes (pack direcciona byte a byte). Esa conversion se ha realizado antes*/
	pack = aux_pointer + ip_ihl;

	/*nivel 4*/

	if(ip_protocol == TCP_CODE){

		printf("Imprimendo campos del nivel 4 (TCP):\n");
		
		lvl4_ports = ntohs(*(uint16_t *) pack);
		printf("\t*Puerto de origen: %u \n", lvl4_ports);
		/* Filtrado del puerto origen */
		if(sport_filter != 0){
			if(sport_filter != lvl4_ports){
				printf("El puerto de origen de TCP de este paquete NO coincide con el del filtro: %u.\nSe aborta la impresion de los siguientes campos.\n\n", sport_filter);
				return;
			}
		}

		pack += 2;

		lvl4_ports = ntohs(*(uint16_t *) pack);
		printf("\t*Puerto de destino: %u\n", lvl4_ports);
		/* Filtrado del puerto destino */
		if(dport_filter != 0){
			if(dport_filter != lvl4_ports){
				printf("El puerto de origen de TCP de este paquete NO coincide con el del filtro: %u.\nSe aborta la impresion de los siguientes campos.\n\n", dport_filter);
				return;
			}
		}
		pack += 11;

		tcp_ack = (pack[0]&0x10)>>4;
		tcp_syn = (pack[0]&0x02)>>1;

		printf("\t*Bandera SYN: %u\n", tcp_syn);
		printf("\t*Bandera ACK: %u\n", tcp_ack);

	}
	else if(ip_protocol == UDP_CODE){

		printf("Imprimendo campos del nivel 4 (UDP):\n");
		
		lvl4_ports = ntohs(*(uint16_t *) pack);
		printf("\t*Puerto de origen: %u \n", lvl4_ports);
		/* Filtrado del puerto origen */
		if(sport_filter != 0){
			if(sport_filter != lvl4_ports){
				printf("El puerto de origen de UDP de este paquete no coincide con el del filtro: %u.\nSe aborta la impresion de los siguientes campos.\n\n", sport_filter);
				return;
			}
		}
		pack += 2;

		lvl4_ports = ntohs(*(uint16_t *) pack);
		printf("\t*Puerto de destino: %u\n", lvl4_ports);
		/* Filtrado del puerto destino */
		if(dport_filter != 0){
			if(dport_filter != lvl4_ports){
				printf("El puerto de origen de UDP de este paquete no coincide con el del filtro: %u.\nSe aborta la impresion de los siguientes campos.\n\n", dport_filter);
				return;
			}
		}
		pack += 2;

		printf("\t*Longitud: %u\n", ntohs(*(uint16_t *) pack));
	}
	else{
		printf("El siguiente protocolo no es el esperado. No se imprimira informacion relativa a los siguientes niveles\n\n");
		return;
	}

	printf("El paquete se ha analizado por completo");
	printf("\n\n");
}

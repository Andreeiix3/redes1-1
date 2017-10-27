/***************************************************************************
 practica2.h

 Compila: make
 Autores: Emilio Cuesta y Pablo Alejo Polania
 2017 EPS-UAM
***************************************************************************/

#ifndef PRACTICA1_H
#define PRACTICA1_H

/********************* Definicion de constantes *************************************************/
#define ETH_ALEN      6                           /* Tamanio de la direccion ethernet           */
#define ETH_HLEN      14                          /* Tamanio de la cabecera ethernet            */
#define ETH_TLEN      2                           /* Tamanio del campo tipo ethernet            */
#define ETH_FRAME_MAX 1514                        /* Tamanio maximo la trama ethernet (sin CRC) */
#define ETH_FRAME_MIN 60                          /* Tamanio minimo la trama ethernet (sin CRC) */
#define ETH_DATA_MAX  (ETH_FRAME_MAX - ETH_HLEN)  /* Tamano maximo y minimo de los datos de una trama ethernet*/
#define ETH_DATA_MIN  (ETH_FRAME_MIN - ETH_HLEN)
#define IP_ALEN 4			                      /* Tamanio de la direccion IP					*/
#define OK 0
#define ERROR 1
#define PACK_READ 1
#define PACK_ERR -1
#define TRACE_END -2
#define NO_FILTER 0
#define TCP_CODE 0x06                             /*Codigo del protocolo TCP*/
#define UDP_CODE 0x11                             /*Codigo del protocolo UDP*/
#define SNAPLENGTH 2048



/*Funciones empleadas*/
void analizar_paquete(const struct pcap_pkthdr *hdr, const uint8_t *pack);

void handleSignal(int nsignal);


#endif /* PRACTICA1_H */

/**@file main.c
 * @brief main - Program, libs, and logging facilities setup and handling
 * @author Tiago Alves Macambira
 * @version $Id: main.c,v 1.21 2004-03-21 02:20:11 tmacam Exp $
 * 
 * 
 * Based on sample code provided with libnids and copyright (c) 1999
 * Rafal Wojtczuk <nergal@avet.com.pl>. All rights reserved.
 * See the file COPYING from libnids for license details.
 *
 *
 * (c) Tiago Alves Macambira
 * See COPYING for licence for further license details
 *
 *
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include "nids.h"
#include "pcap.h"
#include <syslog.h>

#include <errno.h>
#include <pwd.h>
#include <grp.h>
#include <time.h>


#include "main.h"
#include "e2k_utils.h"
#include "e2k_state_machine.h"



/* ********************************************************************  
 *  Global defines - error handling macros 
 * ******************************************************************** */

#define CHECK_IF_NULL(ptr) \
        do { if ( ptr == NULL ) { goto null_error; }}while(0)

/* ********************************************************************  
 *  Global variables - Private to this module
 * ******************************************************************** */

unsigned char e2ksniff_errbuf[256];

pcap_t* pcap_descriptor = NULL;
long int n_connections;
time_t next_syslog_report_time = 0;
int is_sniffing = 0;

inline void syslog_drops(void);
int rotate_logfile( int interval, int max_size );

/* ********************************************************************  
 * Sniffing control functions
 * ******************************************************************** */

inline void handle_tcp_close(struct tcp_stream *a_tcp, conn_state_t **conn_state_ptr)
{
	conn_state_t* conn_state = *conn_state_ptr;
	
	/* Ignore both client and server-side streams */
	a_tcp->client.collect = 0;
	a_tcp->server.collect = 0; 
	
	fprintf(stdout,"%s %s closed\n",strtimestamp(),conn_state->address_str);
	/* free conn. related data */
	free(conn_state);
	*conn_state_ptr=NULL;
	/* connection was closed normally */

	/* Statistics */
	n_connections--;
}

inline void handle_tcp_data(struct tcp_stream *a_tcp, conn_state_t **conn_state_ptr)
{
	static int packets_to_logrotate = LOGROTATE_WITH_N_PACKETS;
	conn_state_t* conn_state = *conn_state_ptr;
	unsigned int discard_amount = 0;
	int debug = 0; /*FIXME*/

	/*Should we process this TCP connection? */
	if (conn_state->ignore){
		fprintf( stdout,
			 "%s %s ignoring\n",
			 strtimestamp(), conn_state->address_str);
		handle_tcp_close(a_tcp,conn_state_ptr);
	}

	/* So, where is this new data comming from? */
	if (a_tcp->client.count_new > 0){
		discard_amount = handle_halfstream_data( IS_CLIENT,
							&a_tcp->client,
							&conn_state->client);
		++debug;
	}
	if (a_tcp->server.count_new > 0){
		discard_amount = handle_halfstream_data( IS_SERVER,
							&a_tcp->server,
							&conn_state->server);
		++debug;
	}

	if(debug > 2){
		fprintf(stderr,"\n\n\n == SERVER AND CLIENT DATA ARRIVED SIMUTANEOUSLY!!!!\n\n\n");
		exit(1);
	}
	nids_discard(a_tcp, discard_amount);
	/* rotate_logfile is expensive... delay it with little overhead */
	if( (packets_to_logrotate--) < 0){
		rotate_logfile(LOGROTATE_INTERVAL, LOGROTATE_MAX_SIZE);
		packets_to_logrotate= LOGROTATE_WITH_N_PACKETS;
	};
}

inline void handle_tcp_establish(struct tcp_stream *a_tcp, conn_state_t **conn_state_ptr)
{
	conn_state_t* conn_state = NULL;

	/* Follow both client and server-side streams 
	 * but don't follow any urgent data strem*/
	a_tcp->client.collect++; 
	a_tcp->server.collect++; 
	
	/* Alloc the state tracking structure */
	conn_state=(conn_state_t *)malloc(sizeof( conn_state_t));
	/* FIXME : check if null*/
	/* Register/link state tracking data with the stream*/
	*conn_state_ptr = conn_state;
	
	/* Setup state tracking structures */
	conn_state->ignore = 0;
	/* - address_str */
	strncpy(conn_state->address_str, address_str(a_tcp->addr),
			CONN_STATE_ADDRESS_STR_SZ -1);
	conn_state->address_str[CONN_STATE_ADDRESS_STR_SZ -1] = '\0';
	/* - client-side state-machine */
	conn_state->client.next_packet_offset = 0;
	conn_state->client.state = wait_full_header;
	conn_state->client.connection = conn_state;
	conn_state->client.blessed = 0;
	/* - server-side state-machine*/
	conn_state->server.next_packet_offset = 0;
	conn_state->server.state = wait_full_header;
	conn_state->server.connection = conn_state;
	conn_state->server.blessed = 0;

	fprintf( stdout,
		 "%s %s established\n",
		 strtimestamp(),conn_state->address_str);

	/* Statistics */
	n_connections++;
	if (time(NULL) > next_syslog_report_time){ /*FIXME not portable*/
		syslog_drops();
		next_syslog_report_time = time(NULL) + SYSLOG_REPORT_INTERVAL;
	}

}



void tcp_callback(struct tcp_stream *a_tcp, conn_state_t **conn_state_ptr)
{
	
	if (a_tcp->nids_state == NIDS_DATA) {
		/* new data has arrived in the stream */
		handle_tcp_data(a_tcp, conn_state_ptr);
	} else	if (a_tcp->nids_state == NIDS_JUST_EST) {
		/* A new connection was established.
		 * Is it a edonkey connection? Should we sniff it?
		 */
		if (a_tcp->addr.dest == EDONKEY_CLIENT_PORT) {
			handle_tcp_establish(a_tcp,conn_state_ptr);
		}
	} else if ( (a_tcp->nids_state == NIDS_CLOSE) ||
	     (a_tcp->nids_state == NIDS_RESET) ||
	     (a_tcp->nids_state == NIDS_TIMED_OUT) ){
		handle_tcp_close(a_tcp,conn_state_ptr);
	};
	return;
}


/* ********************************************************************  
 * Security and resource control functions
 * ******************************************************************** */
/**@brief Callback used by libNIDS to notify that it has run out of memory
 */
void out_of_memory_callback()
{
	fprintf(stdout," == NDIS run out of memory!!!\n");
	fflush(stdout); 
	fprintf(stderr,"NDIS run out of memory!!!\n");
	fflush(stderr);
	syslog( nids_params.syslog_level, " == NIDS run out of memory!!!"); 
	/* FIXME so... now what?! Exit, call a "save yourselves function?" */
	exit(1);
}

/**@brief Drop root privilages 
 *
 * This function will drop any superuser privilage of the current process by
 * setuid-ing into unpriv_user.
 *
 * If, by some unknown reason, unpriv_user is
 * also a superuser, the function will return with error.
 *
 * @param unpriv_user the name of the unprivileged user the process will
 * impersonate.
 *
 * @return 0 in case of success. A non-zero value in case of error.
 */
int drop_privilages(const unsigned char* unpriv_user)
{
	struct passwd *pw = NULL;

	/*FIXME clean the env? */
	
	/* Is there any privileges to be dropped? Am I a superuser? */
	if (getuid() == 0) {
		/* Get unpriv_user's UID and GID */
		if ( (pw = getpwnam (unpriv_user)) == NULL ){
			snprintf( e2ksniff_errbuf,
				  sizeof(e2ksniff_errbuf) -1,
				  "There is no user '%s'",
				  unpriv_user);
			goto error;
		} 
		/* Change GID */
		if ( setgid(pw->pw_gid) != 0 ){
			snprintf( e2ksniff_errbuf,
				 sizeof(e2ksniff_errbuf) -1,
				 "Cannot change GID: %s",
				 strerror(errno) );
			goto error;
		}
		/* Clean the supplementary group ID list*/
		if ( setgroups(0,NULL) != 0 ) {
			snprintf( e2ksniff_errbuf,
				  sizeof(e2ksniff_errbuf) -1,
				  "Could not clen the supplementary group IDs list");
			goto error;
			
		}
		/* Finally, change the UID*/
		if ( setuid(pw->pw_uid) != 0 ){
			snprintf( e2ksniff_errbuf,
				 sizeof(e2ksniff_errbuf) -1,
				 "Cannot change UID: %s",
				 strerror(errno) );
			goto error;
		}		
		/* Am I still a superuser ? 
		 * unpriv_user must be a superuser then. */
		if ( (getuid() == 0) || (getgid() == 0) ) {
			snprintf( e2ksniff_errbuf,
				  sizeof(e2ksniff_errbuf) -1,
				  "%s is a superuser - can't drop privileges by impersonating a superuser: is nonsense, dude!", unpriv_user);
			goto error;
		}
	} 
	
	/* Success */
	return 0;
error:
	return 1;
}

void syslog_drops(void)
{
	struct pcap_stat stat;

	if (is_sniffing) {
	       if (pcap_descriptor == NULL) {
		       pcap_descriptor = nids_getdesc();
	       }
		pcap_stats( pcap_descriptor , &stat);
		syslog( nids_params.syslog_level,
			" == Statistics: Droped Packets: %i, Active Connections: %i, Received Packtes: %i",
			stat.ps_drop,
			n_connections,
			stat.ps_recv);
		/* Eu não confio mais em nada! E chega de comentários
		 * em inglês!*/
		fprintf( stdout,
			 " == Statistics: Droped Packets: %i, Active Connections: %i, Received Packtes: %i",
			 stat.ps_drop,
			n_connections,
			stat.ps_recv);
	}
}

/**@brief Redireciona a STDOUT para um arquivo de texto e realiza um "rotate"
 * neste caso o tamanho deste fique muito grande ou ele esteja aberto a muito
 * tempo.
 *
 * Os arquivos textos (log) são gerados no diretório atual. Essa função não
 * não funciona se não estivermos sniffando a rede (is_sniffing).
 * 
 * @param interval o tempo máximo em segundos que um arquivo pode ficar sem ser
 * rotacionado
 * @param max_size o tamanho máximo em bytes que um arquivo de log pode ter.
 *
 * @return -1 em caso de erros. 0 se tudo ocorrer bem.
 */
int rotate_logfile( int interval, int max_size )
{
	/*FIXME handle errors*/

	static FILE* log_file = NULL;
	static time_t last_rotate = 0; /*FIXME not portable*/

	struct stat st_buff;
	time_t now;
	struct tm* now_tm;
#define FILENAME_LENGTH 100
	unsigned char filename[FILENAME_LENGTH];

	/* If we are not sniffing, no redirection or rotation are done */
	if (!is_sniffing){
		return 0;
	}
	
	/* initialization */
	if ( (time(&now) == (time_t)(-1)) ||
	     ((now_tm = localtime(&now)) == NULL) ||
	     (fstat(STDOUT_FILENO, &st_buff) == -1) ){
		fprintf(stderr,
			" == rotate_logfile initialization error: %s\n",
			strerror(errno));
		return -1;
	}
	
	/* Está na hora de rodar o log? */
	if ( ( log_file == NULL ) || ( st_buff.st_size > max_size ) || 
	     ( (int)difftime(now, last_rotate) > interval) ){
		/* Zera o contador de tempo */
		time(&last_rotate);
		/* Fecha o log-file antigo */
		if( log_file != NULL) {
			fclose(log_file);
		}
		/* Gera o nome do novo log-file */
		if ( strftime(filename,FILENAME_LENGTH-1,"%F-%H-%M-%S.log",
		      now_tm) == 0 ){
			fprintf(stderr," == Não pude criar um nome para o arquivo de log\n");
			return -1;
		}
		/* Abre o novo log-file*/
		if ( (log_file=fopen(filename,"w")) == NULL ){
			fprintf(stderr,
				" == Não pude criar arquivo de log: %s\n",
				strerror(errno));
			return -1;
		}
		/* Fecha a STDOUT */
		close(STDOUT_FILENO);
		/* Liga a STDOUT ao arquivo LOG */
		if( dup2(fileno(log_file),STDOUT_FILENO) != STDOUT_FILENO){
			fprintf(stderr," == Não pude redirecionar a saída padrão para o arquivo de log: %s\n",strerror(errno));
			return -1;
		}	
	}
	return 0;
}

/* ********************************************************************  
 * Main program
 * ******************************************************************** */

int main(int argc, char* argv[])
{
	
	/* Initial local setup - counters, syslog, etc */
	n_connections = 0;
	is_sniffing = 0;
	next_syslog_report_time = time(NULL);
	pcap_descriptor = NULL; /* setted @ syslog_drops() */
	openlog("e2ksniff", 0, LOG_LOCAL0);
	
	/* Setup libNIDS - defaults */
	nids_params.device = "any";
	nids_params.pcap_filter = "port 4662";
	nids_params.one_loop_less = 0; /* We depend of this semantic */
	nids_params.scan_num_hosts = 0; /* Turn port-scan detection off */
	nids_params.no_mem = out_of_memory_callback;
	nids_params.n_hosts=1024*16; /* FIXME value too small? */
	nids_params.n_tcp_streams = 1024*128;
	nids_params.sk_buff_size = 1024*64;

	/* Load recorded trace-file or sniff the network?*/
	if (argc > 1){
		nids_params.device = NULL;
		nids_params.filename = argv[1];
		fprintf(stdout," == Loading trace file: %s\n",nids_params.filename );
		is_sniffing = 0;
	} else {
		fprintf(stdout," == No tracefile given. Sniffing from the network.\n");
		is_sniffing = 1;
	}

	/* Start libNIDS engine */
	if (!nids_init()) {
		fprintf(stderr, " == ERROR: libNIDS error: %s\n", nids_errbuf);
		exit(1);
	}

	/*  DROP PRIVILEGES !!!!  */
	if( (is_sniffing) && 
	    (drop_privilages(UNPRIV_USER) != 0) ){
		fprintf( stderr, " == ERROR: Could not drop privileges: %s\n",
			e2ksniff_errbuf);
		exit(1);
	} else {
		fprintf( stdout,
			 " == Droped privilages. Impersonating '%s'\n",
			 UNPRIV_USER);
	}

	nids_register_tcp(tcp_callback);
	
	/* STDOUT Redirection ang log rotation */
	if (is_sniffing){
		fprintf( stdout,
			 " == Starting STDOUT redirection and log rotation\n");
		if( rotate_logfile(LOGROTATE_INTERVAL,LOGROTATE_MAX_SIZE) < 0){
			syslog( nids_params.syslog_level,
				" == ERROR: Could not logrotate");
			fprintf( stderr, " == ERROR: Could not logrotate\n");
			exit(1);
		}
	} else {
		fprintf( stdout,
			 " == Not sniffing: logging on STDOUT\n");
	}
		
	/* Go, speed racer, go! */
	syslog( nids_params.syslog_level," == Sniffing started.");
	fprintf(stdout," == Sniffing started.\n");
	nids_run(); /* Loop forever*/

	/* We were not supposed to get here */	
	syslog( nids_params.syslog_level," == Sniffing stopped - ERROR?");
	fprintf(stdout," == Sniffing stopped - ERROR?\n");
	fprintf(stderr," == Sniffing stopped - ERROR?\n");

	return 0;
}

/**@file main.c
 * @brief main - Program, libs, and logging facilities setup and handling
 * @author Tiago Alves Macambira
 * @version $Id: main.c,v 1.18 2004-03-18 14:52:42 tmacam Exp $
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
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include "nids.h"
#include "pcap.h"
#include <syslog.h>

/*para strerror*/
#include <errno.h>
/*para drop_privilages*/
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

/* ********************************************************************  
 * Sniffing control functions
 * ******************************************************************** */

inline void handle_tcp_close(struct tcp_stream *a_tcp, conn_state_t **conn_state_ptr)
{
	conn_state_t* conn_state = *conn_state_ptr;
	
	/* Ignore both client and server-side streams */
	a_tcp->client.collect = 0;
	a_tcp->server.collect = 0; 
	
	fprintf(stdout, "%s closed\n", conn_state->address_str);
	/* free conn. related data */
	free(conn_state);
	*conn_state_ptr=NULL;
	/* connection was closed normally */

	/* Statistics */
	n_connections--;
}

inline void handle_tcp_data(struct tcp_stream *a_tcp, conn_state_t **conn_state_ptr)
{
	conn_state_t* conn_state = *conn_state_ptr;
	unsigned int discard_amount = 0;
	int debug = 0; /*FIXME*/

	/*Should we process this TCP connection? */
	if (conn_state->ignore){
		fprintf( stdout, "%s ignoring\n", conn_state->address_str);
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

	fprintf(stdout, "%s established\n", conn_state->address_str);

	/* Statistics */
	n_connections++;
	if (time(NULL) > next_syslog_report_time){
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
	}
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
		printf(" == Loading trace file: %s\n",nids_params.filename );
		is_sniffing = 0;
	} else {
		printf(" == No tracefile given. Sniffing from the network.\n");
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
	
	printf(" == Sniffing started.\n");
	syslog( nids_params.syslog_level," == Sniffing started.");
	nids_run(); /* Loop forever*/
	return 0;
}

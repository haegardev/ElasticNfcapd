/*   Experiment: Index netflow records captured by nfcapd with elasticseach
 *   Copyright (C) 2013  Gerard Wagener
 * 
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU Affero General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU Affero General Public License for more details.
 *
 *   You should have received a copy of the GNU Affero General Public License
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */  
#define _XOPEN_SOURCE       /* See feature_test_macros(7) */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <libnfdump/libnfdump.h>
#include <curl/curl.h>
#include <assert.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include <getopt.h>
#define URLROOT "http://localhost:9200/test2/test/"
#define BASEURL "http://localhost:9200"
#define IMPORTCHUNKS 10 
#define SIZE_PER_CHUNK 300 
#define NUM_REPLICAS 2
#define NUM_SHARDS 3
/* Disable this for suppressing curl debug messages */
#define DEBUGCURL 
#define ERRSIZE 1024

#ifdef WORDS_BIGENDIAN
#   define ntohll(n)    (n)
#   define htonll(n)    (n)
#else
#   define ntohll(n)    (((uint64_t)ntohl(n)) << 32) + ntohl((n) >> 32)
#   define htonll(n)    (((uint64_t)htonl(n)) << 32) + htonl((n) >> 32)
#endif

int num_shards;
int num_repl;

void *xalloc(size_t nmemb, size_t size)
{
    void *buf;
    buf = calloc(nmemb,size);
    assert(buf);
    return buf;
}

typedef struct curl_write_user_s {
    size_t reply_size;
    char* replymsg;
} curl_write_user_t;

size_t fetch_reply(char *ptr, size_t size, size_t nmemb, void *userdata)
{
    curl_write_user_t* params;
    params = (curl_write_user_t*)userdata;
    return snprintf(params->replymsg, params->reply_size, "%s",ptr);     
}


int build_json_doc(char* jsonbuffer, size_t size, master_record_t* r)
{
    char as[40];
    char ds[40];
    char firstseen[20];
    char lastseen[20];
    struct tm tm;
    if ( (r->flags & FLAG_IPV6_ADDR ) != 0 ) { // IPv6
    r->v6.srcaddr[0] = htonll(r->v6.srcaddr[0]);
        r->v6.srcaddr[1] = htonll(r->v6.srcaddr[1]);
        r->v6.dstaddr[0] = htonll(r->v6.dstaddr[0]);
        r->v6.dstaddr[1] = htonll(r->v6.dstaddr[1]);
        inet_ntop(AF_INET6, r->v6.srcaddr, as, sizeof(as));
        inet_ntop(AF_INET6, r->v6.dstaddr, ds, sizeof(ds));
    } else {    // IPv4
        r->v4.srcaddr = htonl(r->v4.srcaddr);
        r->v4.dstaddr = htonl(r->v4.dstaddr);
        inet_ntop(AF_INET, &r->v4.srcaddr, as, sizeof(as));
        inet_ntop(AF_INET, &r->v4.dstaddr, ds, sizeof(ds));
    }
    as[40-1] = 0;
    ds[40-1] = 0;
    snprintf((char*)&firstseen, 32, "%d", r->first);
    if (strptime(firstseen, "%s",&tm)) {
        strftime((char*)&firstseen, 32, "%Y%m%d %H:%M:%S",&tm);
        snprintf((char*)&lastseen,  32, "%d", r->last);  
        if (strptime(lastseen, "%s",&tm)) {
            strftime((char*)&lastseen, 32, "%Y%m%d %H:%M:%S", &tm);
            //TODO check bytes and endianness of ports
            //TODO test integer encoding for IPaddresses
            return snprintf(jsonbuffer, size,"{\"firstseen\":\"%s\",\
\"lastseen\":\"%s\", \"srcaddr\":\"%s\", \"dstaddr\":\"%s\",\"srcport\":\"%d\",\
\"dstport\":%d, \"bytes\":%ld,\"flows\":%ld,\"srcas\":%d,\"dstas\":%d}", 
firstseen, lastseen, as, ds, r->srcport, r->dstport, r->out_bytes, 
r->aggr_flows, r->srcas,r->dstas);
        }
    }
    /* Return 0 on errors  -> means that the broken packets will be 
     * overwritten with the new packets */    
    return 0;
}

/* Sends the jsondoc to the URL using HTTP post requests.
 * The reply of the server is put in the reply message having the size 
 * reply_size. The HTTP error code is returned on success. On errors 
 * -1 is returned.
 */ 
int send_json_request(CURL* curl, char* url, char* jsondoc, char* replymsg, 
                      size_t reply_size)
{
    struct curl_slist* headers;
    int http_code;
    CURLcode res;
    curl_write_user_t* params;
    
    headers = NULL;
    http_code = -1; /* There was an error somewhere */
    params = xalloc(1,sizeof(curl_write_user_t));

    #ifdef DEBUGCURL 
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
    #endif
    curl_easy_setopt(curl, CURLOPT_POST,1L); 
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PUT");
    headers = curl_slist_append(headers, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers); 
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, jsondoc);

    params->replymsg = replymsg;
    params->reply_size = reply_size; 
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, params);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &fetch_reply);
    /* Do the request */
    res = curl_easy_perform(curl);
    
    if (res == CURLE_OK) {
        curl_easy_getinfo (curl, CURLINFO_RESPONSE_CODE, &http_code);
    }  else{
        fprintf(stderr,"[ERROR] Could not create index code: %d\n",res);
    }
    curl_slist_free_all(headers);    
    /* There was an error somewhere */
    return http_code;
}

/* Create an explicit mapping netflow records 
 * The mapping is sent to the baseurl
 * indexname is the name of the index that is accessed
 * doctype is the name of the document type that is addressed with this 
 * mapping
 * FIXME this mapping should be optimized with better core types of 
 * elasticsearch
 */
int create_mapping(char* baseurl, char* indexname, char* doctype)
{
    char *url;
    char* payload;
    char* reply;
    int r;
    CURL* curl;
    url = xalloc(1,1024);
    payload = xalloc(1,1024);
    reply = xalloc(1,1024);
    /* Default error value */
    r = 0; 
    snprintf(url, 1024, "%s/%s/%s/_mapping",baseurl, indexname, doctype);
    snprintf(payload, 1024,"\
      {\"nfrecord\": {\
      \"properties\" : {\
        \"bytes\" : {\
          \"type\" : \"long\"\
        },\
        \"dstaddr\" : {\
          \"type\" : \"string\"\
        },\
        \"dstas\" : {\
          \"type\" : \"long\"\
        },\
        \"dstport\" : {\
          \"type\" : \"long\"\
        },\
        \"firstseen\" : {\
          \"type\" : \"string\"\
        },\
        \"flows\" : {\
          \"type\" : \"long\"\
        },\
        \"lastseen\" : {\
          \"type\" : \"string\"\
        },\
        \"srcaddr\" : {\
          \"type\" : \"string\"\
        },\
        \"srcas\" : {\
          \"type\" : \"long\"\
        },\
        \"srcport\" : {\
          \"type\" : \"string\"\
        }\
       }\
      }\
     }");
    printf("%s\n",payload);
    curl = curl_easy_init();
    r = send_json_request(curl, url, payload, reply, 1024);
    if (r == 200) {
        /* All went fine */
        r = 1;
    } else {
        fprintf(stderr,"[ERROR] Mapping failed. HTTP return code: %d\n",r);
        fprintf(stderr, "[ERROR] Mapping reply: %s\n", reply);
        r = 0;
    }
    /* Cleanup */
    free(reply);
    
    return r;
}

    

/* Creates an index on elasticsearch server specified by the baseurl parameter
 * The index is defined with the indexname parameter
 *
 * Returns 1 on success
 * Returns 0 on error
 */
int create_index(char* baseurl, char* indexname)
{
    CURL* curl;
    char *payload;
    char *url;
    int r;
    char* reply;

    reply = xalloc(1,1024);
    
    r = 0; /* Default: error */
    
    payload = xalloc(1024,1);
    url = xalloc(1024,1);
    
    curl = curl_easy_init();
    snprintf(url, 1024, "%s/%s",baseurl, indexname);
    snprintf(payload, 1024, "{\
\"settings\" : {\
        \"index\" : {\
            \"number_of_shards\" : %d,\
            \"number_of_replicas\" : %d\
        }\
    }\
}", num_shards, num_repl);  
    r = send_json_request(curl, url, payload, reply, 1024);
    if (r == 200) {
        /* Assume that the request went fine and ignore the reply */
        r = 1;
    }   else {
        fprintf(stderr,"[ERROR] Could not create index. Cause = %s\n",
                reply);
        r = 0;    
    }
    /* Clean up */
    free(url);
    free(payload);
    free(reply);
    curl_easy_cleanup(curl);
    return r;
}



void init(void)
{
    num_shards = NUM_SHARDS;
    num_repl = NUM_REPLICAS;
}

int process_nfcapd_files(char* filename)
{
    libnfstates_t* states;
    master_record_t* rec;
    CURL* curl;
    char* jsonbuf;
    CURLcode res;
    struct curl_slist *headers;
    char* url;
    long cnt;
    char *p;
    size_t rsize; //remaining size
    size_t num_bytes;
    
    init();

    headers = NULL;
    jsonbuf = calloc(IMPORTCHUNKS*SIZE_PER_CHUNK,1);
    rsize = IMPORTCHUNKS * SIZE_PER_CHUNK;
    url = calloc(128,1);
    assert(url);
    assert(jsonbuf);
    p = jsonbuf;

    cnt = 0;
    curl = curl_easy_init();
    curl_easy_setopt(curl, CURLOPT_POST,1L); 
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PUT");
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
    headers = curl_slist_append(headers, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers); 
    states = initlib(NULL, filename, NULL);
    if (states) {
        do {
            rec = get_next_record(states);
            if (rec) {
                cnt++;
                /* Fill the buffer */
                //printf("DEBUG: rsize: %ld\n",rsize);
                num_bytes = build_json_doc(p, rsize,rec);
                //printf("DEBUG: num_bytes: %ld\n",num_bytes);
                //printf("DEBUG: %s\n",jsonbuf);
                p+=num_bytes;
                rsize-=num_bytes;
                if (rsize < SIZE_PER_CHUNK) { 
                    //printf("DEBUG: There is not enough space for placing the next chunk %ld\n",rsize);
                    jsonbuf[0] = 0;
                    p = jsonbuf;
                    rsize = IMPORTCHUNKS * SIZE_PER_CHUNK;
                }
                /* TODO  build here a bulk message for elastic search
                 * FIXME depends on the previously used mapping, so fix
                 * optimize the mapping first
                 */
                continue;
                snprintf(url, 128,"%s%ld",URLROOT,cnt); 
                curl_easy_setopt(curl, CURLOPT_URL, url);

                curl_easy_setopt(curl, CURLOPT_POSTFIELDS, jsonbuf);
              
                res = curl_easy_perform(curl);
                if (res != CURLE_OK) {
                    fprintf(stderr,"curl_easy_perform failed %s request=%s\n",
                            curl_easy_strerror(res), jsonbuf);
                    continue;
                }
                //printf("[INFO] sent request %s to %s\n",jsonbuf,url);
            }
        } while (rec);
      //TODO free slists
     } 
    return EXIT_SUCCESS;
}

int main(int argc, char* argv[])
{
    char *nfcapdfilename;
    int next_option;
    const char* short_options = "hcr:";
    const struct option long_options [] = {
        {   "help"  , 0 , NULL, 'h'  },
        {   "create", 0,  NULL, 'c'  },
        {   "read",   0,  NULL, 'r'  },
        {   NULL,     0,  NULL, 0    }
    };
   
    do {
        next_option = getopt_long(argc, argv, short_options, 
                                  long_options, NULL);
        switch ( next_option ) {
            case 'h':
                printf("Print help screen\n");
                break;
            case 'c':
                printf("Crerate the index and its mapping\n");
                break;
            case 'r':
                nfcapdfilename = optarg;
                printf("Index the nfcapd file %s\n",nfcapdfilename);
                break;
            case -1:
                break;
            default:
                return EXIT_FAILURE;
        }
    } while ( next_option != -1 ); 
    
    return EXIT_SUCCESS;
}

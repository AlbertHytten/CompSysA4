#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <time.h>

#ifdef __APPLE__
#include "./endian.h"
#else
#include <endian.h>
#endif

#include "./peer.h"
#include "./sha256.h"
#include <stddef.h>


// Global variables to be used by both the server and client side of the peer.
// Some of these are not currently used but should be considered STRONG hints
PeerAddress_t *my_address;

pthread_mutex_t network_mutex = PTHREAD_MUTEX_INITIALIZER;
PeerAddress_t** network = NULL;
uint32_t peer_count = 0;

pthread_mutex_t retrieving_mutex = PTHREAD_MUTEX_INITIALIZER;
FilePath_t** retrieving_files = NULL;
uint32_t file_count = 0;


/*
 * Gets a sha256 hash of specified data, sourcedata. The hash itself is
 * placed into the given variable 'hash'. Any size can be created, but a
 * a normal size for the hash would be given by the global variable
 * 'SHA256_HASH_SIZE', that has been defined in sha256.h
 */
void get_data_sha(const char* sourcedata, hashdata_t hash, uint32_t data_size, 
    int hash_size)
{
  SHA256_CTX shactx;
  unsigned char shabuffer[hash_size];
  sha256_init(&shactx);
  sha256_update(&shactx, sourcedata, data_size);
  sha256_final(&shactx, shabuffer);

  for (int i=0; i<hash_size; i++)
  {
    hash[i] = shabuffer[i];
  }
}

/*
 * Gets a sha256 hash of specified data file, sourcefile. The hash itself is
 * placed into the given variable 'hash'. Any size can be created, but a
 * a normal size for the hash would be given by the global variable
 * 'SHA256_HASH_SIZE', that has been defined in sha256.h
 */
void get_file_sha(const char* sourcefile, hashdata_t hash, int size)
{
    int casc_file_size;

    FILE* fp = fopen(sourcefile, "rb");
    if (fp == 0)
    {
        printf("Failed to open source: %s\n", sourcefile);
        return;
    }

    fseek(fp, 0L, SEEK_END);
    casc_file_size = ftell(fp);
    fseek(fp, 0L, SEEK_SET);

    char buffer[casc_file_size];
    fread(buffer, casc_file_size, 1, fp);
    fclose(fp);

    get_data_sha(buffer, hash, casc_file_size, size);
}

/*
 * A simple min function, which apparently C doesn't have as standard
 */
uint32_t min(int a, int b)
{
    if (a < b) 
    {
        return a;
    }
    return b;
}

/*
 * Select a peer from the network at random, without picking the peer defined
 * in my_address
 */
void get_random_peer(PeerAddress_t* peer_address)
{ 
    PeerAddress_t** potential_peers = malloc(sizeof(PeerAddress_t*));
    uint32_t potential_count = 0; 
    for (uint32_t i=0; i<peer_count; i++)
    {
        if (strcmp(network[i]->ip, my_address->ip) != 0 
                || strcmp(network[i]->port, my_address->port) != 0 )
        {
            potential_peers = realloc(potential_peers, 
                (potential_count+1) * sizeof(PeerAddress_t*));
            potential_peers[potential_count] = network[i];
            potential_count++;
        }
    }

    if (potential_count == 0)
    {
        printf("No peers to connect to. You probably have not implemented "
            "registering with the network yet.\n");
    }

    uint32_t random_peer_index = rand() % potential_count;

    memcpy(peer_address->ip, potential_peers[random_peer_index]->ip, IP_LEN);
    memcpy(peer_address->port, potential_peers[random_peer_index]->port, 
        PORT_LEN);

    free(potential_peers);

    printf("Selected random peer: %s:%s\n", 
        peer_address->ip, peer_address->port);
}

/*
 * Send a request message to another peer on the network. Unless this is 
 * specifically an 'inform' message as described in the assignment handout, a 
 * reply will always be expected.
 */
void send_message(PeerAddress_t peer_address, int command, char* request_body, 
    int request_len)
{
    fprintf(stdout, "Connecting to server at %s:%s to run command %d (%s)\n", 
        peer_address.ip, peer_address.port, command, request_body);

    compsys_helper_state_t state;
    char msg_buf[MAX_MSG_LEN];
    FILE* fp;

    // Setup the eventual output file path. This is being done early so if 
    // something does go wrong at this stage we can avoid all that pesky 
    // networking
    char output_file_path[request_len+1];
    memset(output_file_path, '\0', request_len + 1);
    if (command == COMMAND_RETREIVE)
    {     
        strcpy(output_file_path, request_body);

        if (access(output_file_path, F_OK ) != 0 ) 
        {
            fp = fopen(output_file_path, "a");
            fclose(fp);
        }
    }

    // Setup connection
    int peer_socket = compsys_helper_open_clientfd(peer_address.ip, peer_address.port);
    compsys_helper_readinitb(&state, peer_socket);

    // Construct a request message and send it to the peer
    struct RequestHeader request_header;
    strncpy(request_header.ip, my_address->ip, IP_LEN);
    request_header.port = htonl(atoi(my_address->port));
    request_header.command = htonl(command);
    request_header.length = htonl(request_len);

    memcpy(msg_buf, &request_header, REQUEST_HEADER_LEN);
    memcpy(msg_buf+REQUEST_HEADER_LEN, request_body, request_len);

    compsys_helper_writen(peer_socket, msg_buf, REQUEST_HEADER_LEN+request_len);

    // We don't expect replies to inform messages so we're done here
    if (command == COMMAND_INFORM)
    {
        return;
    }

    // Read a reply
    compsys_helper_readnb(&state, msg_buf, REPLY_HEADER_LEN);

    // Extract the reply header 
    char reply_header[REPLY_HEADER_LEN];
    memcpy(reply_header, msg_buf, REPLY_HEADER_LEN);

    uint32_t reply_length = ntohl(*(uint32_t*)&reply_header[0]);
    uint32_t reply_status = ntohl(*(uint32_t*)&reply_header[4]);
    uint32_t this_block = ntohl(*(uint32_t*)&reply_header[8]);
    uint32_t block_count = ntohl(*(uint32_t*)&reply_header[12]);
    hashdata_t block_hash;
    memcpy(block_hash, &reply_header[16], SHA256_HASH_SIZE);
    hashdata_t total_hash;
    memcpy(total_hash, &reply_header[48], SHA256_HASH_SIZE);

    // Determine how many blocks we are about to recieve
    hashdata_t ref_hash;
    memcpy(ref_hash, &total_hash, SHA256_HASH_SIZE);
    uint32_t ref_count = block_count;

    // Loop until all blocks have been recieved
    for (uint32_t b=0; b<ref_count; b++)
    {
        // Don't need to re-read the first block
        if (b > 0)
        {
            // Read the response
            compsys_helper_readnb(&state, msg_buf, REPLY_HEADER_LEN);

            // Read header
            memcpy(reply_header, msg_buf, REPLY_HEADER_LEN);

            // Parse the attributes
            reply_length = ntohl(*(uint32_t*)&reply_header[0]);
            reply_status = ntohl(*(uint32_t*)&reply_header[4]);
            this_block = ntohl(*(uint32_t*)&reply_header[8]);
            block_count = ntohl(*(uint32_t*)&reply_header[12]);

            memcpy(block_hash, &reply_header[16], SHA256_HASH_SIZE);
            memcpy(total_hash, &reply_header[48], SHA256_HASH_SIZE);

            // Check we're getting consistent results
            if (ref_count != block_count)
            {
                fprintf(stdout, 
                    "Got inconsistent block counts between blocks\n");
                close(peer_socket);
                return;
            }

            for (int i=0; i<SHA256_HASH_SIZE; i++)
            {
                if (ref_hash[i] != total_hash[i])
                {
                    fprintf(stdout, 
                        "Got inconsistent total hashes between blocks\n");
                    close(peer_socket);
                    return;
                }
            }
        }

        // Check response status
        if (reply_status != STATUS_OK)
        {
            if (command == COMMAND_REGISTER && reply_status == STATUS_PEER_EXISTS)
            {
                printf("Peer already exists\n");
            }
            else
            {
                printf("Got unexpected status %d\n", reply_status);
                close(peer_socket);
                return;
            }
        }

        // Read the payload
        char payload[reply_length+1];
        compsys_helper_readnb(&state, msg_buf, reply_length);
        memcpy(payload, msg_buf, reply_length);
        payload[reply_length] = '\0';
        
        // Check the hash of the data is as expected
        hashdata_t payload_hash;
        get_data_sha(payload, payload_hash, reply_length, SHA256_HASH_SIZE);

        for (int i=0; i<SHA256_HASH_SIZE; i++)
        {
            if (payload_hash[i] != block_hash[i])
            {
                fprintf(stdout, "Payload hash does not match specified\n");
                close(peer_socket);
                return;
            }
        }

        // If we're trying to get a file, actually write that file
        if (command == COMMAND_RETREIVE)
        {
            // Check we can access the output file
            fp = fopen(output_file_path, "r+b");
            if (fp == 0)
            {
                printf("Failed to open destination: %s\n", output_file_path);
                close(peer_socket);
            }

            uint32_t offset = this_block * (MAX_MSG_LEN-REPLY_HEADER_LEN);
            fprintf(stdout, "Block num: %d/%d (offset: %d)\n", this_block+1, 
                block_count, offset);
            fprintf(stdout, "Writing from %d to %d\n", offset, 
                offset+reply_length);

            // Write data to the output file, at the appropriate place
            fseek(fp, offset, SEEK_SET);
            fputs(payload, fp);
            fclose(fp);
        }
    }

    // Confirm that our file is indeed correct
    if (command == COMMAND_RETREIVE)
    {
        fprintf(stdout, "Got data and wrote to %s\n", output_file_path);

        // Finally, check that the hash of all the data is as expected
        hashdata_t file_hash;
        get_file_sha(output_file_path, file_hash, SHA256_HASH_SIZE);

        for (int i=0; i<SHA256_HASH_SIZE; i++)
        {
            if (file_hash[i] != total_hash[i])
            {
                fprintf(stdout, "File hash does not match specified for %s\n", 
                    output_file_path);
                close(peer_socket);
                return;
            }
        }
    }

    // If we are registering with the network we should note the complete 
    // network reply
    char* reply_body = malloc(reply_length + 1);
    memset(reply_body, 0, reply_length + 1);
    memcpy(reply_body, msg_buf, reply_length);

    if (reply_status == STATUS_OK)
    {
        if (command == COMMAND_REGISTER)
        {
            // Update the network list with the received peers
            pthread_mutex_lock(&network_mutex);
            for (uint32_t i = 0; i < reply_length; i += (IP_LEN + sizeof(uint32_t)))
            {
                char peer_ip[IP_LEN];
                uint32_t peer_port;
                memcpy(peer_ip, reply_body + i, IP_LEN);
                peer_port = ntohl(*(uint32_t*)(reply_body + i + IP_LEN));

                // Convert peer_port to string
                char peer_port_str[PORT_LEN];
                snprintf(peer_port_str, PORT_LEN, "%d", peer_port);

                // Check if the peer already exists in the network list
                int exists = 0;
                for (uint32_t j = 0; j < peer_count; j++) {
                    if (strcmp(network[j]->ip, peer_ip) == 0 && strcmp(network[j]->port, peer_port_str) == 0) {
                        exists = 1;
                        break;
                    }
                }
                if (!exists) {
                    // Add the new peer to the network list
                    PeerAddress_t* new_peer = malloc(sizeof(PeerAddress_t));
                    strncpy(new_peer->ip, peer_ip, IP_LEN);
                    strncpy(new_peer->port, peer_port_str, PORT_LEN);
                    network = realloc(network, (peer_count + 1) * sizeof(PeerAddress_t*));
                    network[peer_count] = new_peer;
                    peer_count++;
                }
            }
            pthread_mutex_unlock(&network_mutex);
        }
    } 
    else
    {
        printf("Got response code: %d, %s\n", reply_status, reply_body);
    }
    free(reply_body);
    close(peer_socket);
}

void build_and_send_responses(int connfd, int status, char* to_send, uint32_t to_send_len) {
    // Calculate the total checksum of the data to send
    hashdata_t total_checksum;
    get_data_sha(to_send, total_checksum, to_send_len, SHA256_HASH_SIZE);

    // Calculate how long the payload can be
    uint32_t sendable_length = MAX_MSG_LEN - REPLY_HEADER_LEN;

    // Calculate the number of blocks
    uint32_t blocks_count = (to_send_len + sendable_length - 1) / sendable_length;
    uint32_t this_block = 0;

    // Loop to send one or more blocks of payload
    for (uint32_t offset = 0; offset < to_send_len; offset += sendable_length) {
        // Determine the length of this block's payload
        uint32_t this_payload_length = (offset + sendable_length > to_send_len) ? (to_send_len - offset) : sendable_length;

        // Calculate the checksum of this block
        hashdata_t block_checksum;
        get_data_sha(to_send + offset, block_checksum, this_payload_length, SHA256_HASH_SIZE);

        // Construct the reply header
        struct ReplyHeader reply_header;
        reply_header.length = htonl(this_payload_length);
        reply_header.status = htonl(status);
        reply_header.this_block = htonl(this_block);
        reply_header.block_count = htonl(blocks_count);
        memcpy(reply_header.block_hash, block_checksum, SHA256_HASH_SIZE);
        memcpy(reply_header.total_hash, total_checksum, SHA256_HASH_SIZE);

        // Send the reply header
        compsys_helper_writen(connfd, &reply_header, REPLY_HEADER_LEN);

        // Send the payload
        compsys_helper_writen(connfd, to_send + offset, this_payload_length);

        this_block++;
    }
}

/*
 * Function to act as thread for all required client interactions. This thread 
 * will be run concurrently with the server_thread but is finite in nature.
 * 
 * This is just to register with a network, then download two files from a 
 * random peer on that network. As in A3, you are allowed to use a more 
 * user-friendly setup with user interaction for what files to retrieve if 
 * preferred, this is merely presented as a convienient setup for meeting the 
 * assignment tasks
 */ 
void* client_thread(void* thread_args) {
    // struct PeerAddress *peer_address = thread_args;

    // // Register the given user
    // send_message(*peer_address, COMMAND_REGISTER, "", 0);

    // // Update peer_address with random peer from network
    // get_random_peer(peer_address);

    // // Retrieve the smaller file, that doesn't not require support for blocks
    // send_message(*peer_address, COMMAND_RETREIVE, "tiny.txt", 8);

    // // Update peer_address with random peer from network
    // get_random_peer(peer_address);

    // // Retrieve the larger file, that requires support for blocked messages
    // send_message(*peer_address, COMMAND_RETREIVE, "hamlet.txt", 10);
    // return NULL;
}

/*
 * Handle any 'register' type requests, as defined in the asignment text. This
 * should always generate a response.
 */
void handle_register(int connfd, char* client_ip, int client_port_int) {
    // Convert client_port_int to string
    char client_port[PORT_LEN];
    snprintf(client_port, PORT_LEN, "%d", client_port_int);

    // Add the new peer to the network list
    pthread_mutex_lock(&network_mutex);
    // Check if the peer already exists in the network list
    for (uint32_t i = 0; i < peer_count; i++) {
        if (strcmp(network[i]->ip, client_ip) == 0 && strcmp(network[i]->port, client_port) == 0) {
            pthread_mutex_unlock(&network_mutex);
            // Send response indicating peer already exists
            build_and_send_responses(connfd, STATUS_PEER_EXISTS, "", 0);
            close(connfd);
            return; // Peer already exists, no need to add
        }
    }
    // Add the new peer to the network list
    PeerAddress_t* new_peer = malloc(sizeof(PeerAddress_t));
    strncpy(new_peer->ip, client_ip, IP_LEN);
    strncpy(new_peer->port, client_port, PORT_LEN);
    network = realloc(network, (peer_count + 1) * sizeof(PeerAddress_t*));
    network[peer_count] = new_peer;
    peer_count++;
    pthread_mutex_unlock(&network_mutex);

    // Construct the reply containing the entire network list
    uint32_t reply_length = peer_count * (IP_LEN + sizeof(uint32_t));
    char* reply_body = malloc(reply_length);
    char* ptr = reply_body;
    for (uint32_t i = 0; i < peer_count; i++) {
        memcpy(ptr, network[i]->ip, IP_LEN);
        ptr += IP_LEN;
        uint32_t port = htonl(atoi(network[i]->port));
        memcpy(ptr, &port, sizeof(uint32_t));
        ptr += sizeof(uint32_t);
    }

    // Send the reply
    build_and_send_responses(connfd, STATUS_OK, reply_body, reply_length);

    free(reply_body);
    close(connfd);
}

/*
 * Handle 'inform' type message as defined by the assignment text. These will 
 * never generate a response, even in the case of errors.
 */
void handle_inform(char* request) {
    // Extract the new peer's IP and port from the request
    char new_peer_ip[IP_LEN];
    uint32_t new_peer_port;
    memcpy(new_peer_ip, request, IP_LEN);
    new_peer_port = ntohl(*(uint32_t*)(request + IP_LEN));

    // Convert new_peer_port to string for comparison
    char new_peer_port_str[PORT_LEN];
    snprintf(new_peer_port_str, PORT_LEN, "%d", new_peer_port);

    // Add the new peer to the network list
    pthread_mutex_lock(&network_mutex);
    // Check if the peer already exists in the network list
    for (uint32_t i = 0; i < peer_count; i++) {
        if (strcmp(network[i]->ip, new_peer_ip) == 0 && strcmp(network[i]->port, new_peer_port_str) == 0) {
            pthread_mutex_unlock(&network_mutex);
            return; // Peer already exists, no need to add
        }
    }
    // Add the new peer to the network list
    PeerAddress_t* new_peer = malloc(sizeof(PeerAddress_t));
    strncpy(new_peer->ip, new_peer_ip, IP_LEN);
    strncpy(new_peer->port, new_peer_port_str, PORT_LEN);
    network = realloc(network, (peer_count + 1) * sizeof(PeerAddress_t*));
    network[peer_count] = new_peer;
    peer_count++;
    pthread_mutex_unlock(&network_mutex);
}

/*
 * Handle 'retrieve' type messages as defined by the assignment text. This will
 * always generate a response
 */
void handle_retreive(int connfd, char* request) {
    // Get the requested file path
    char file_path[PATH_LEN];
    strncpy(file_path, request, PATH_LEN);

    // Check if the file exists
    if (access(file_path, F_OK) != 0) {
        // File does not exist, send an error response
        build_and_send_responses(connfd, STATUS_BAD_REQUEST, "File not found", strlen("File not found"));
        close(connfd);
        return;
    }

    // Open the file for reading
    FILE* fp = fopen(file_path, "rb");
    if (fp == NULL) {
        // Failed to open the file, send an error response
        build_and_send_responses(connfd, STATUS_BAD_REQUEST, "Failed to open file", strlen("Failed to open file"));
        close(connfd);
        return;
    }

    // Get the file size
    fseek(fp, 0, SEEK_END);
    uint32_t file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    // Read the file content into a buffer
    char* file_content = malloc(file_size);
    fread(file_content, 1, file_size, fp);
    fclose(fp);

    // Send the file content as a response
    build_and_send_responses(connfd, STATUS_OK, file_content, file_size);

    free(file_content);
    close(connfd);
}

/*
 * Handler for all server requests. This will call the relevent function based 
 * on the parsed command code
 */
void handle_server_request_thread(int   connfd) {
    compsys_helper_state_t state;
    compsys_helper_readinitb(&state, connfd);

    // Read the request header
    char request_header[REQUEST_HEADER_LEN];
    compsys_helper_readnb(&state, request_header, REQUEST_HEADER_LEN);

    // Parse the request header
    char client_ip[IP_LEN];
    uint32_t client_port, command, request_length;
    memcpy(client_ip, request_header, IP_LEN);
    client_port = ntohl(*(uint32_t*)(request_header + IP_LEN));
    command = ntohl(*(uint32_t*)(request_header + IP_LEN + sizeof(uint32_t)));
    request_length = ntohl(*(uint32_t*)(request_header + IP_LEN + 2 * sizeof(uint32_t)));

    // Read the request body
    char* request_body = malloc(request_length + 1);
    compsys_helper_readnb(&state, request_body, request_length);
    request_body[request_length] = '\0';

    // Handle the request based on the command
    if (command == COMMAND_REGISTER) {
        handle_register(connfd, client_ip, client_port);
    } else if (command == COMMAND_INFORM) {
        handle_inform(request_body);
    } else if (command == COMMAND_RETREIVE) {
        handle_retreive(connfd, request_body);
    } else {
        // Unknown command, send an error response
        build_and_send_responses(connfd, STATUS_BAD_REQUEST, "Unknown command", strlen("Unknown command"));
        close(connfd);
    }

    free(request_body);
}

/*
 * Function to act as basis for running the server thread. This thread will be
 * run concurrently with the client thread, but is infinite in nature.
 */
void* server_thread() {
    int server_socket, client_socket;
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);

    // Open a listening socket
    server_socket = compsys_helper_open_listenfd(my_address->port);
    if (server_socket < 0) {
        perror("Failed to open listening socket");
        exit(EXIT_FAILURE);
    }

    printf("Starting server at %s:%s\n", my_address->ip, my_address->port);

    // Accept and handle incoming connections
    while (1) {
        client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &client_len);
        if (client_socket < 0) {
            perror("Accept failed");
            continue;
        }
        // Handle the client request in a separate thread
        pthread_t client_thread;
        if (pthread_create(&client_thread, NULL, (void*(*)(void*))handle_server_request_thread, (void*)(intptr_t)client_socket) != 0) {
            perror("Thread creation failed");
            close(client_socket);
            continue;
        }
        // Detach the thread so that it cleans up after itself
        pthread_detach(client_thread);
    }

    // Close the server socket
    close(server_socket);
    return NULL;
}


int main(int argc, char **argv)
{
    // Initialise with known junk values, so we can test if these were actually
    // present in the config or not
    struct PeerAddress peer_address;
    memset(peer_address.ip, '\0', IP_LEN);
    memset(peer_address.port, '\0', PORT_LEN);
    memcpy(peer_address.ip, "x", 1);
    memcpy(peer_address.port, "x", 1);

    // Users should call this script with a single argument describing what 
    // config to use
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s <config file>\n", argv[0]);
        exit(EXIT_FAILURE);
    } 

    my_address = (PeerAddress_t*)malloc(sizeof(PeerAddress_t));
    memset(my_address->ip, '\0', IP_LEN);
    memset(my_address->port, '\0', PORT_LEN);

    // Read in configuration options. Should include a client_ip, client_port, 
    // server_ip, and server_port
    char buffer[128];
    fprintf(stderr, "Got config path at: %s\n", argv[1]);
    FILE* fp = fopen(argv[1], "r");
    while (fgets(buffer, 128, fp)) {
        if (starts_with(buffer, MY_IP)) {
            memcpy(&my_address->ip, &buffer[strlen(MY_IP)], 
                strcspn(buffer, "\r\n")-strlen(MY_IP));
            if (!is_valid_ip(my_address->ip)) {
                fprintf(stderr, ">> Invalid client IP: %s\n", my_address->ip);
                exit(EXIT_FAILURE);
            }
        }else if (starts_with(buffer, MY_PORT)) {
            memcpy(&my_address->port, &buffer[strlen(MY_PORT)], 
                strcspn(buffer, "\r\n")-strlen(MY_PORT));
            if (!is_valid_port(my_address->port)) {
                fprintf(stderr, ">> Invalid client port: %s\n", 
                    my_address->port);
                exit(EXIT_FAILURE);
            }
        }else if (starts_with(buffer, PEER_IP)) {
            memcpy(peer_address.ip, &buffer[strlen(PEER_IP)], 
                strcspn(buffer, "\r\n")-strlen(PEER_IP));
            if (!is_valid_ip(peer_address.ip)) {
                fprintf(stderr, ">> Invalid peer IP: %s\n", peer_address.ip);
                exit(EXIT_FAILURE);
            }
        }else if (starts_with(buffer, PEER_PORT)) {
            memcpy(peer_address.port, &buffer[strlen(PEER_PORT)], 
                strcspn(buffer, "\r\n")-strlen(PEER_PORT));
            if (!is_valid_port(peer_address.port)) {
                fprintf(stderr, ">> Invalid peer port: %s\n", 
                    peer_address.port);
                exit(EXIT_FAILURE);
            }
        }
    }
    fclose(fp);

    retrieving_files = malloc(file_count * sizeof(FilePath_t*));
    srand(time(0));

    network = malloc(sizeof(PeerAddress_t*));
    network[0] = my_address;
    peer_count = 1;

    // Setup the client and server threads 
    pthread_t client_thread_id;
    pthread_t server_thread_id;
    if (peer_address.ip[0] != 'x' && peer_address.port[0] != 'x')
    {   
        pthread_create(&client_thread_id, NULL, client_thread, &peer_address);
    } 
    pthread_create(&server_thread_id, NULL, server_thread, NULL);

    // Start the threads. Note that the client is only started if a peer is 
    // provided in the config. If none is we will assume this peer is the first
    // on the network and so cannot act as a client.
    if (peer_address.ip[0] != 'x' && peer_address.port[0] != 'x')
    {
        pthread_join(client_thread_id, NULL);
    }
    pthread_join(server_thread_id, NULL);

    exit(EXIT_SUCCESS);
}
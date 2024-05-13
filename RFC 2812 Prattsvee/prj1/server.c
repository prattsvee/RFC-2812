#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <ctype.h>
#include <time.h>
#include <asm-generic/socket.h>
#define CONFIG_FILE "server.conf"
#include "base64_utils.h"

// Now you can use base64_encode and base64_decode as needed


#define BUFFER_SIZE 1024
#define MAX_CLIENTS 25
#define MAX_CHANNELS 25
#define CHANNEL_NAME_LEN 50
#define MAX_NICK_LENGTH 20

#define ERR_NEEDMOREPARAMS 101
#define ERR_TOOMANYPARAMS 102
#define ERR_CHANNELISFULL 103
#define ERR_NOSUCHCHANNEL 104
#define ERR_TOOMANYCHANNELS 105
#define ERR_TOOMANYTARGETS 106
#define ERR_UNAVAILRESOURCE 107
#define ERR_NORECIPIENT 304
#define ERR_NOTEXTTOSEND 306
#define ERR_NOSUCHNICK 309

#define ERR_NOTONCHANNEL 201
#define ERR_NOSUCHNICK_OR_NOSUCHCHANNEL 401
#define ERR_TOOMANYMATCHES 301
#define ERR_NOSUCHSERVER 302
#define ERR_NOSUCHSERVER 402
#define RPL_TIME 391
#define RPL_NOTOPIC 393
#define ERR_ALREADYREGISTERED 462 //Prj2




char NICK[BUFFER_SIZE]; // Declare NICK as a global variable 
int PORT; // Declare PORT as a global variable

void send_error(int client_socket, int error_code)
{
    const char *error_message;
    switch (error_code)
    {
    case ERR_NEEDMOREPARAMS:
        error_message = "Error 101: Need more parameters";
        break;
    case ERR_TOOMANYPARAMS:
        error_message = "Error 102: Too many parameters";
        break;
    case ERR_CHANNELISFULL:
        error_message = "Error 103: Channel is full";
        break;
    case ERR_NOSUCHCHANNEL:
        error_message = "Error 104: No such channel";
        break;
    case ERR_TOOMANYCHANNELS:
        error_message = "Error 105: Too many channels";
        break;
    case ERR_TOOMANYTARGETS:
        error_message = "Error 106: Too many targets";
        break;
    case ERR_UNAVAILRESOURCE:
        error_message = "Error 107: Unavailable resource";
        break;
    case ERR_NOTONCHANNEL:
        error_message = "Error 201: Not on channel";
        break;
    case ERR_TOOMANYMATCHES:
        error_message = "Error 301: Too many matches";
        break;
    case ERR_NOSUCHSERVER:
        error_message = "Error 302: No such server";
        break;
    case ERR_NORECIPIENT:
        error_message = ":%s 411 :No recipient given (PRIVMSG)\n";
        break;
    case ERR_NOTEXTTOSEND:
        error_message = ":%s 412 :No text to send\n";
        break;
    case ERR_NOSUCHNICK_OR_NOSUCHCHANNEL:
        error_message = ":%s 401 :No such nick/channel\n";
        break;
    case RPL_NOTOPIC:
        error_message = "No topic";
    default:
        error_message = "Unknown error";
    }

    send(client_socket, error_message, strlen(error_message), 0);
    printf("Sent to client %d: %s\n", client_socket, error_message);
}

char nicknames[MAX_CLIENTS][MAX_NICK_LENGTH]; // Array to store nicknames

typedef struct {
    char nickname[MAX_NICK_LENGTH];
    char realname[BUFFER_SIZE];
    char password[BUFFER_SIZE];  // Store the password for verification
    int client_socket;
    int password_received;       // Flag to indicate password has been set
    int is_registered;           // Flag to check if user is fully registered
} UserInfo;

UserInfo user_info[MAX_CLIENTS]; // Array to store user information


UserInfo user_info[MAX_CLIENTS]; // Array to store user information

typedef struct
{

    char channelName[CHANNEL_NAME_LEN];
    int clients[MAX_CLIENTS];
    int clientCount;
    char topic[BUFFER_SIZE];
} Channel;





Channel channels[MAX_CHANNELS];
int channelCount = 0;

void *handle_client(void *arg);
void handle_nick_command(int client_socket, const char *nickname);
void handle_user_command(int client_socket, const char *nickname, const char *realname);
void join_channel(int client_socket, const char *channelName);
void part_channel(int client_socket, const char *channelName);
void set_or_get_topic(int client_socket, const char *channelName, const char *topic);
void list_names(int client_socket, const char *channelName);
void handle_privmsg(int client_socket, const char *msgtarget, const char *message);
void remove_extra_spaces(char *str);
void handle_time_command(int client_socket);
void read_config(char *server_ip, int *port);

void read_config(char *server_ip, int *port) {
    FILE *fp;
    char line[100];

    fp = fopen(CONFIG_FILE, "r");
    if (fp == NULL) {
        perror("Error opening configuration file");
        exit(EXIT_FAILURE);
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        char *key = strtok(line, "=");
        char *value = strtok(NULL, "=");

        if (value == NULL) {
            continue;
        }

        // Remove trailing newline character
        value[strcspn(value, "\n")] = '\0';

        if (strcmp(key, "NICK") == 0) {
            strcpy(server_ip, value);
        } else if (strcmp(key, "PORT") == 0) {
            *port = atoi(value);
        }
    }

    fclose(fp);
}

int main()
{
    int server_fd, new_socket;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);

    // Read configuration from server.conf
    read_config(NICK, &PORT);

    // Creating socket file descriptor
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0)
    {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    // Forcefully attaching socket to the port
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt)))
    {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0)
    {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, MAX_CLIENTS) < 0)
    {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    while (1)
    {
        if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t *)&addrlen)) < 0)
        {
            perror("accept");
            exit(EXIT_FAILURE);
        }

        // Populate user_info with client information
        int index;
        for (index = 0; index < MAX_CLIENTS; index++)
        {
            if (user_info[index].client_socket == 0)
            { // Find an empty slot in user_info array
                user_info[index].client_socket = new_socket;
                printf("Client connected with socket %d\n", user_info[index].client_socket); // Debug output
                break;
            }
        }

        pthread_t tid;
        if (pthread_create(&tid, NULL, handle_client, (void *)&new_socket) != 0)
        {
            perror("pthread_create");
            close(new_socket);
        }
    }

    return 0;
}

void *handle_client(void *arg) {
    int client_socket = *(int *)arg;
    char buffer[BUFFER_SIZE];
    char client_ip[INET_ADDRSTRLEN];

    // Get client's IP address
    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);
    if (getpeername(client_socket, (struct sockaddr *)&client_addr, &addr_len) == 0) {
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
        printf("Client IP: %s\n", client_ip);
    } else {
        printf("Error getting client IP\n");
    }

    while (1) {
        memset(buffer, 0, BUFFER_SIZE);
        int read_bytes = read(client_socket, buffer, BUFFER_SIZE - 1);
        if (read_bytes <= 0) {
            printf("Client %s disconnected.\n", client_ip);
            break; // Exit the loop if client disconnected
        }

        printf("Received message from client: %s\n", buffer);
        char *command = strtok(buffer, " ");
        if (!command) {
            continue;
        }

        // Handle PASS command at any time
        if (strcmp(command, "PASS") == 0) {
            char *password = strtok(NULL, " ");
            if (password) {
                // Use the modified handle_pass_command function which also logs
                handle_pass_command(client_socket, password);
            } else {
                send_error(client_socket, ERR_NEEDMOREPARAMS);
            }
        } else if (strcmp(command, "NICK") == 0) {
            char *nickname = strtok(NULL, " ");
            if (nickname) {
                handle_nick_command(client_socket, nickname);
            } else {
                send_error(client_socket, ERR_NEEDMOREPARAMS);
            }
        } else if (strcmp(command, "USER") == 0) {
            char *nickname = strtok(NULL, " ");
            char *realname = strtok(NULL, ":\r\n");
            if (nickname && realname) {
                handle_user_command(client_socket, nickname, realname);
            } else {
                send_error(client_socket, ERR_NEEDMOREPARAMS);
            }
        } else if (strcmp(command, "JOIN") == 0) {
            char *channelName = strtok(NULL, " ");
            if (channelName) {
                join_channel(client_socket, channelName);
            } else {
                send_error(client_socket, ERR_NEEDMOREPARAMS);
            }
        } else if (strcmp(command, "PART") == 0) {
            char *channelName = strtok(NULL, " ");
            if (channelName) {
                part_channel(client_socket, channelName);
            } else {
                send_error(client_socket, ERR_NEEDMOREPARAMS);
            }
        } else if (strcmp(command, "TOPIC") == 0) {
            char *channelName = strtok(NULL, " ");
            char *topic = strtok(NULL, "\r\n");
            set_or_get_topic(client_socket, channelName, topic);
        } else if (strcmp(command, "NAMES") == 0) {
            char *channelName = strtok(NULL, " ");
            list_names(client_socket, channelName);
        } else if (strcmp(command, "QUIT") == 0) {
            printf("Client %s quit.\n", client_ip);
            char response[BUFFER_SIZE];
            strcpy(response, "BYE");
            send(client_socket, response, strlen(response), 0);
            break; // Exit the loop if client sends QUIT command
        } else if (strcmp(command, "PRIVMSG") == 0) {
            char *msgtarget = strtok(NULL, " ");
            char *message = strtok(NULL, "\r\n");
            if (msgtarget && message) {
                handle_privmsg(client_socket, msgtarget, message);
            } else {
                send_error(client_socket, ERR_NORECIPIENT);
            }
        } else if (strstr(command, "TIME") != NULL) {
            handle_time_command(client_socket);
        } else {
            printf("Unknown command from client: %s\n", command);
        }
    }

    close(client_socket);
    pthread_exit(NULL);
}




void handle_pass_command(int client_socket, const char *password) {
    // Directly use the client_socket to find the user in the user_info array
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (user_info[i].client_socket == client_socket) {
            // Store the password directly
            strncpy(user_info[i].password, password, BUFFER_SIZE - 1);
            user_info[i].password[BUFFER_SIZE - 1] = '\0';
            printf("Password received and saved: %s\n", password);

            // Save the password to the file
            save_password_to_file(client_socket, password);
            return;
        }
    }
    printf("Error: Client socket %d not found in user_info array.\n", client_socket);
}

void save_password_to_file(int client_socket, const char *password) {
    FILE *file = fopen(".usr_pass", "a");  // Open the file in append mode
    if (file == NULL) {
        perror("Failed to open password file");
        return;
    }
    fprintf(file, "%d:%s\n", client_socket, password);
    fclose(file);
    printf("Password for socket %d saved successfully in .usr_pass file.\n", client_socket);
}





void handle_nick_command(int client_socket, const char *nickname)
{
    // Check if the nickname is already in use
    int nick_in_use = 0;
    for (int i = 0; i < MAX_CLIENTS; i++)
    {
        if (strcmp(user_info[i].nickname, nickname) == 0)
        {
            nick_in_use = 1;
            break;
        }
    }

    if (!nick_in_use)
    {
        // iterste in a for loop and find where the socket for nick is in the array and store the nickname at that index
        int index;
        for (index = 0; index < MAX_CLIENTS; index++)
        {
            if (user_info[index].client_socket == client_socket)
            {
                // Match found, copy the nickname and break out of the loop
                strncpy(user_info[index].nickname, nickname, MAX_NICK_LENGTH - 1);
                user_info[index].nickname[MAX_NICK_LENGTH - 1] = '\0'; // Ensure null-termination
                break;
            }
        }

        if (index == MAX_CLIENTS)
        {
            // Handle case when client_socket is not found in the array
            printf("Client socket not found in the array.\n");
        }
        printf("Client %d set nickname to %s\n", client_socket, user_info[index].nickname);
        // Send RPL_NICK
        char reply_msg[BUFFER_SIZE];
        snprintf(reply_msg, BUFFER_SIZE, ":%s 401 %s %s :Nickname is now %s\n", NICK, user_info[index].nickname, user_info[index].nickname, user_info[index].nickname);
        write(client_socket, reply_msg, strlen(reply_msg));
    }
    else
    {
        // Send ERR_NICKNAMEINUSE
        char err_msg[BUFFER_SIZE];
        snprintf(err_msg, BUFFER_SIZE, ":%s 433 %s %s :Nickname is already in use\n", NICK, user_info[client_socket].nickname, user_info[client_socket].nickname);
        write(client_socket, err_msg, strlen(err_msg));
    }
}


void handle_user_command(int client_socket, const char *nickname, const char *realname)
{
    int client_index = -1;

    // Find the index of user_info for the given client_socket
    for (int i = 0; i < MAX_CLIENTS; i++)
    {
        if (user_info[i].client_socket == client_socket)
        {
            client_index = i;
            break;
        }
    }

    // Check if the nickname is already set for any other client
    for (int i = 0; i < MAX_CLIENTS; i++)
    {
        if (strcmp(user_info[i].nickname, nickname) == 0 && user_info[i].client_socket != client_socket)
        {
            // Nickname is already set for a different client, send ERR_NICKNAMEINUSE
            char err_msg[BUFFER_SIZE];
            snprintf(err_msg, BUFFER_SIZE, ":%s 433 %s %s :Nickname is already in use\n", NICK, user_info[i].nickname, user_info[i].nickname);
            write(client_socket, err_msg, strlen(err_msg));
            return;
        }
    }

    if (client_index != -1 && strlen(user_info[client_index].nickname) > 0)
    {
        // Nickname is already set, send RPL_WELCOME directly without registering again
        // Send RPL_WELCOME
        char welcome_msg[BUFFER_SIZE];
        snprintf(welcome_msg, BUFFER_SIZE, ":%s 001 %s :Welcome to the IRC network %s!%s@%s\n", NICK, user_info[client_index].nickname, user_info[client_index].nickname, user_info[client_index].nickname, NICK);
        write(client_socket, welcome_msg, strlen(welcome_msg));
    }
    else
    {
        // Nickname not set or client not found, proceed with registration
        if (client_index != -1)
        {
            // Store user information
            strncpy(user_info[client_index].nickname, nickname, MAX_NICK_LENGTH - 1);
            user_info[client_index].nickname[MAX_NICK_LENGTH - 1] = '\0';
            strncpy(user_info[client_index].realname, realname, BUFFER_SIZE - 1);
            user_info[client_index].realname[BUFFER_SIZE - 1] = '\0';

            // Send RPL_WELCOME
            char welcome_msg[BUFFER_SIZE];
            snprintf(welcome_msg, BUFFER_SIZE, ":%s 001 %s :Welcome to the IRC network %s!%s@%s\n", NICK, user_info[client_index].nickname, user_info[client_index].nickname, user_info[client_index].nickname, NICK);
            write(client_socket, welcome_msg, strlen(welcome_msg));
        }
        else
        {
            // Handle case when client_socket is not found in the array
            printf("Client socket not found in the array.\n");
        }
    }
}





void join_channel(int client_socket, const char *channelName)
{
    char response[BUFFER_SIZE];

    if (channelName == NULL || strlen(channelName) == 0)
    {
        send_error(client_socket, ERR_NEEDMOREPARAMS);
        return;
    }

    if (channelCount >= MAX_CHANNELS)
    {
        send_error(client_socket, ERR_TOOMANYCHANNELS);
        return;
    }

    if (strcmp(channelName, "0") == 0)
    {
        // User requested to leave all channels
        for (int i = 0; i < channelCount; i++)
        {
            for (int j = 0; j < channels[i].clientCount; j++)
            {
                if (channels[i].clients[j] == client_socket)
                {
                    // Remove client from channel
                    for (int k = j; k < channels[i].clientCount - 1; k++)
                    {
                        channels[i].clients[k] = channels[i].clients[k + 1];
                    }
                    channels[i].clientCount--;
                    break;
                }
            }
        }

        snprintf(response, BUFFER_SIZE, "You have left all channels.\n");
        send(client_socket, response, strlen(response), 0);
        return;
    }

    printf("Client %d attempting to join channel %s\n", client_socket, channelName);
    int found = 0;
    for (int i = 0; i < channelCount; i++)
    {
        if (strcmp(channels[i].channelName, channelName) == 0)
        {
            found = 1;
            if (channels[i].clientCount >= MAX_CLIENTS)
            {
                send_error(client_socket, ERR_CHANNELISFULL);
                return;
            }
            channels[i].clients[channels[i].clientCount++] = client_socket;
            snprintf(response, BUFFER_SIZE, "Client %d joined channel %s\n", client_socket, channelName);
            send(client_socket, response, strlen(response), 0);
            return;
        }
    }

    if (!found)
    {
        Channel newChannel;
        strncpy(newChannel.channelName, channelName, CHANNEL_NAME_LEN);
        newChannel.channelName[CHANNEL_NAME_LEN - 1] = '\0';
        newChannel.clients[0] = client_socket;
        newChannel.clientCount = 1;
        channels[channelCount++] = newChannel;
        snprintf(response, BUFFER_SIZE, "Channel %s created and client %d joined.\n", channelName, client_socket);
        send(client_socket, response, strlen(response), 0);
    }
}

void part_channel(int client_socket, const char *channelName)
{
    char response[BUFFER_SIZE];

    if (channelName == NULL || strlen(channelName) == 0)
    {
        send_error(client_socket, ERR_NEEDMOREPARAMS);
        return;
    }

    printf("Client %d attempting to leave channel %s\n", client_socket, channelName);
    int found = 0;
    for (int i = 0; i < channelCount; i++)
    {
        if (strcmp(channels[i].channelName, channelName) == 0)
        {
            found = 1;
            int clientFound = 0;
            for (int j = 0; j < channels[i].clientCount; j++)
            {
                if (channels[i].clients[j] == client_socket)
                {
                    for (int k = j; k < channels[i].clientCount - 1; k++)
                    {
                        channels[i].clients[k] = channels[i].clients[k + 1];
                    }
                    channels[i].clientCount--;
                    snprintf(response, BUFFER_SIZE, "Client %d left channel %s\n", client_socket, channelName);
                    send(client_socket, response, strlen(response), 0);
                    clientFound = 1;
                    break;
                }
            }
            if (!clientFound)
            {
                send_error(client_socket, ERR_NOTONCHANNEL);
            }
            break;
        }
    }

    if (!found)
    {
        send_error(client_socket, ERR_NOSUCHCHANNEL);
    }
}

void set_or_get_topic(int client_socket, const char *channelName, const char *topic)
{
    char response[BUFFER_SIZE];

    if (channelName == NULL || strlen(channelName) == 0)
    {
        send_error(client_socket, ERR_NEEDMOREPARAMS);
        return;
    }

    int found = 0;
    for (int i = 0; i < channelCount; i++)
    {
        if (strcmp(channels[i].channelName, channelName) == 0)
        {
            found = 1;
            if (topic == NULL)
            {
                if (strlen(channels[i].topic) > 0)
                {
                    snprintf(response, BUFFER_SIZE, "Topic for %s is %s\n", channelName, channels[i].topic);
                    send(client_socket, response, strlen(response), 0);
                }
                else
                {
                    send_error(client_socket, RPL_NOTOPIC);
                }
            }
            else
            {
                strncpy(channels[i].topic, topic, sizeof(channels[i].topic) - 1);
                channels[i].topic[sizeof(channels[i].topic) - 1] = '\0';
                snprintf(response, BUFFER_SIZE, "Topic for %s set to %s\n", channelName, topic);
                send(client_socket, response, strlen(response), 0);
            }
            return;
        }
    }

    if (!found)
    {
        send_error(client_socket, ERR_NOSUCHCHANNEL);
    }
}

void list_names(int client_socket, const char *channelName)
{
    char response[BUFFER_SIZE * MAX_CLIENTS]; // Make sure this buffer is large enough

    int found = 0;
    if (channelName == NULL)
    {
        strcpy(response, "Listing all channels and users:\n");
        for (int i = 0; i < channelCount; i++)
        {
            snprintf(response + strlen(response), sizeof(response) - strlen(response), "Channel: %s\n", channels[i].channelName);
            for (int j = 0; j < channels[i].clientCount; j++)
            {
                for (int k = 0; k < MAX_CLIENTS; k++)
                {
                    if (user_info[k].client_socket == channels[i].clients[j])
                    {
                        snprintf(response + strlen(response), sizeof(response) - strlen(response), "User: %s\n", user_info[k].nickname);
                        break;
                    }
                }
            }
        }
        send(client_socket, response, strlen(response), 0);
    }
    else
    {
        for (int i = 0; i < channelCount; i++)
        {
            if (strcmp(channels[i].channelName, channelName) == 0)
            {
                found = 1;
                snprintf(response, sizeof(response), "Channel: %s\n", channels[i].channelName);
                for (int j = 0; j < channels[i].clientCount; j++)
                {
                    for (int k = 0; k < MAX_CLIENTS; k++)
                    {
                        if (user_info[k].client_socket == channels[i].clients[j])
                        {
                            snprintf(response + strlen(response), sizeof(response) - strlen(response), "User: %s\n", user_info[k].nickname);
                            break;
                        }
                    }
                }
                break;
            }
        }

        if (!found)
        {
            send_error(client_socket, ERR_NOSUCHCHANNEL);
        }
        else
        {
            send(client_socket, response, strlen(response), 0);
        }
    }
}

void handle_privmsg(int client_socket, const char *msgtarget, const char *message)
{
    char response[BUFFER_SIZE];
    remove_extra_spaces(msgtarget);

    printf("Handling PRIVMSG: target=%s, message=%s\n", msgtarget, message);

    if (!msgtarget || !message)
    {
        send_error(client_socket, ERR_NORECIPIENT);
        return;
    }

    if (strlen(message) == 0)
    {
        send_error(client_socket, ERR_NOTEXTTOSEND);
        return;
    }

    // Assume msgtarget can be a nickname or channel
    int found = 0;
    if (msgtarget[0] == '#')
    { // Channel message
        for (int i = 0; i < channelCount; i++)
        {
            printf("Checking channel: %s\n", channels[i].channelName);
            if (strcmp(channels[i].channelName, msgtarget) == 0)
            {
                found = 1;
                printf("Channel found: %s\n", msgtarget);
                for (int j = 0; j < channels[i].clientCount; j++)
                {
                    if (channels[i].clients[j] != client_socket)
                    {
                        snprintf(response, BUFFER_SIZE, "%s: %s\n", msgtarget, message);
                        printf("Sending message to client %d in channel %s\n", channels[i].clients[j], msgtarget);
                        send(channels[i].clients[j], response, strlen(response), 0);
                    }
                }
                break;
            }
        }
        if (!found)
        {
            send_error(client_socket, ERR_NOSUCHCHANNEL);
        }
    }
    else
    { // Private message to a user
        for (int i = 0; i < MAX_CLIENTS; i++)
        {
            remove_extra_spaces(user_info[i].nickname);
            printf("Checking nickname: %s with msgtarget %s\n", user_info[i].nickname, msgtarget);
            if (strcmp(user_info[i].nickname, msgtarget) == 0)
            {
                found = 1;
                printf("Nickname found: %s with socket %d\n", msgtarget, user_info[i].client_socket);
                snprintf(response, BUFFER_SIZE, "From %s: %s\n", user_info[client_socket].nickname, message);
                // printf("Sending private message to %s (socket %d)\n", msgtarget, user_info[i].client_socket);
                send(user_info[i].client_socket, response, strlen(response), 0);
                printf("Sending private message to %s (socket %d)\n", msgtarget, user_info[i].client_socket);
                break;
            }
        }
        if (!found)
        {
            send_error(client_socket, ERR_NOSUCHNICK);
        }
    }
}

void remove_extra_spaces(char *str)
{
    int i, j;
    int length = strlen(str);
    int space_flag = 0; // Flag to track if space was encountered

    // Iterate through the string
    for (i = 0, j = 0; i < length; i++)
    {
        // Skip newline characters
        if (str[i] == '\n')
        {
            continue;
        }
        // If current character is not whitespace or if space_flag is not set
        if (!isspace((unsigned char)str[i]) || !space_flag)
        {
            str[j++] = str[i];                           // Copy the character to the new position
            space_flag = isspace((unsigned char)str[i]); // Update space_flag
        }
    }
    str[j] = '\0'; // Null-terminate the modified string
}

void handle_time_command(int client_socket)
{
    char response[BUFFER_SIZE];
    time_t now;
    struct tm *local_time;

    time(&now);
    local_time = localtime(&now);

    // No target specified or target is this server, send the local time
    strftime(response, BUFFER_SIZE, ":%s 391 :Local time is %H:%M:%S\n", local_time);
    send(client_socket, response, strlen(response), 0);
}
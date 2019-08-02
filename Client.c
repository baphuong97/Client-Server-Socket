#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define PORT 4444
const int NUM_INTERFACE = 2;
int i;

struct control{
	char interface[50], alias[50], mode[50];
};

struct lan{
	char interface[50], rule[50], proto[50], srcip[50], srcmac[50], mask[50];
};

void show(struct control list[])
{
	printf("Interface Alias\t   Filter Rule Mode\n");
	for (i = 1; i < NUM_INTERFACE; i++)
	{
		printf("%s\t", list[i].interface);
		printf("%s\t", list[i].alias);
		printf("%s\t", list[i].mode);
		printf("\n");
	}
}

void show_rule(struct lan _lan)
{
	printf("Rule updated!\n");
	printf("Interface:\t%s\n", _lan.interface);
	printf("Rule:\t%s\n", _lan.rule);
	printf("Protocol:\t%s\n", _lan.proto);
	printf("Source IP:\t%s\n", _lan.srcip);
	printf("Source MAC:\t%s\n", _lan.srcmac);
	printf("Mac mask:\t%s\n", _lan.mask);
}

int true_ip(char ip[])
{
	char *p;
	int tmp;
	p = strtok(ip, ".");
	while (p!=NULL)
	{
		tmp = atoi(p);
		if(tmp < 0 || tmp >255) return 0;
		p = strtok(NULL, ".");
	}
	return 1;
}

int main()
{
	int clientSocket, ret;
	struct sockaddr_in serverAddr;
	char buffer[1024];

	struct control list_control[5];
	
	clientSocket = socket(AF_INET, SOCK_STREAM, 0);
	if (clientSocket < 0)
	{
		printf("[-]Error in connection.\n");
		exit(1);
	}
	printf("[+]Client Socket is created.\n");

	memset(&serverAddr, '\0', sizeof(serverAddr));
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons(PORT);
	serverAddr.sin_addr.s_addr = inet_addr("10.72.113.5");	
	ret = connect(clientSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr));
	
	if (ret < 0)
	{
		printf("[-]Error in connection.\n");
		exit(1);
	}

	printf("[+]Connected to Server.\n");
	printf("LOGIN TO SERVER\n");
	printf("User name: \t");
	scanf("%s", &buffer[0]);
	send(clientSocket,buffer,50,0);
	printf("Password: \t");
	scanf("%s", &buffer[0]);
	send(clientSocket,buffer,50,0);
	char sta[50];
	recv(clientSocket,sta,50,0);
	if (0 != strcmp(sta, "Wellcome Admin!"))
        {
            printf("Wrong password!\n");
        }
	
	while (0 != strcmp(sta,"Wellcome Admin!"))
	{
    		memset(buffer, '\0', 50);
		printf("LOGIN TO SERVER\n");
		printf("User name: \t");
		scanf("%s", &buffer[0]);
		send(clientSocket,buffer,50,0);
		printf("Password: \t");
		scanf("%s", &buffer[0]);
		send(clientSocket,buffer,50,0);
		recv(clientSocket,sta,50,0);
		printf("Wrong password!\n");
	}
	
	printf("=== WELLCOME ADMIN===\n");
	for (i = 1; i < NUM_INTERFACE; i++)
	{
		recv(clientSocket, list_control[i].interface, 50, 0);
		recv(clientSocket, list_control[i].alias, 50, 0);
		recv(clientSocket, list_control[i].mode, 50, 0);
	}
	show(list_control);
	
	while (1)
	{
		printf("Client: \t");
		scanf("%s", &buffer[0]);
		send(clientSocket, buffer, 1024, 0);
		if (0 == strcmp(buffer, ":exit"))
		{
			close(clientSocket);
			printf("[-]Disconnected from server.\n");
			exit(1);
		}
		
		if (0 == strcmp(buffer, "set"))
		{
			scanf("%s", &buffer[0]);
			send(clientSocket, buffer, 50, 0);
			scanf("%s", &buffer[0]);
			send(clientSocket, buffer, 50, 0);
			char status[50] = "False!";
			recv(clientSocket, status, 50, 0);
			printf("%s\n", status);
			
			for (i = 1; i < NUM_INTERFACE; i++)
			{
				recv(clientSocket, list_control[i].interface, 50, 0);
				recv(clientSocket, list_control[i].alias, 50, 0);
				recv(clientSocket, list_control[i].mode, 50, 0);
			}
			
			show(list_control);
			printf("Client set: %s\n", status);
		}
		
		else if (0 == strcmp(buffer, "block"))
		{
			scanf("%s", buffer);
			send(clientSocket, buffer, 1024, 0);
			
			if (0 == strcmp(buffer, "ip"))
			{
				char ip[50], status[50];
				scanf("%s", ip);
				send(clientSocket, ip, 50, 0);
				recv(clientSocket, status, 50, 0);
				if (0 == strcmp(status, "Wrong IP!"))
				{
					printf("%s\n", status);
					continue;
				}
				char size[5];
				recv(clientSocket, size, 10, 0);
				printf("%d\n", atoi(size));
				printf("Black list IP:\n");
				for (i = 0; i < atoi(size); i++)
				{
					recv(clientSocket, ip, 50, 0);
					printf("%s\n", ip);
				}
				printf("%s\n", status);
			}
			
			if (0 == strcmp(buffer, "rangeIP"))
			{
				char ip[50], status[50];
				scanf("%s", ip);
				send(clientSocket, ip, 50, 0);
				recv(clientSocket, status, 50, 0);
				char size[5];
				recv(clientSocket, size, 10, 0);
				printf("%d\n", atoi(size));
				printf("BlackList IP:\n");
				for (i = 0; i < atoi(size); i++)
				{
					recv(clientSocket, ip, 50, 0);
					printf("%s\n", ip);
				}
				printf("%s\n", status);
			}
			
			if (0 == strcmp(buffer, "all"))
			{
				char status[50];
				recv(clientSocket, status,50,0);
				printf("%s\n",status);
			}
			
			if (strcmp(buffer, "mac"))
			{
				char mac[50], status[50];
				scanf("%s", mac);
				send(clientSocket, mac, 50, 0);
				recv(clientSocket, status, 50, 0);
				char size[5];
				recv(clientSocket, size, 10, 0);
				printf("%d\n", atoi(size));
				printf("BlackList MAC:\n");
				for(i = 0; i < atoi(size); i++)
				{
					recv(clientSocket, mac, 50, 0);
					printf("%s\n", mac);
				}
				printf("%s\n", status);
			}
		}
		
		else if (0 == strcmp(buffer, "allow"))
		{
			scanf("%s", buffer);
			send(clientSocket, buffer, 1024, 0);
			if (0 == strcmp(buffer, "ip"))
			{
				char ip[50], status[50];
				scanf("%s", ip);
				send(clientSocket, ip, 50, 0);
				recv(clientSocket, status, 50, 0);
				if (0 == strcmp(status, "Wrong IP!"))
				{
					printf("%s\n", status);
					continue;
				}
				char size[5];
				recv(clientSocket, size, 10, 0);
				printf("%d\n", atoi(size));
				printf("WhiteList IP:\n");
				for (i = 0; i < atoi(size); i++)
				{
					recv(clientSocket, ip, 50, 0);
					printf("%s\n", ip);
				}
				printf("%s\n", status);
			}
			
			if (0 == strcmp(buffer, "rangeIP"))
			{
				char ip[50], status[50];
				scanf("%s", ip);
				send(clientSocket, ip, 50, 0);
				recv(clientSocket, status, 50, 0);
				if (0 == strcmp(status, "Wrong IP!"))
				{
					printf("%s\n", status);
					continue;
				}
				char size[5];
				recv(clientSocket, size, 10, 0);
				printf("%d\n", atoi(size));
				printf("WhiteList IP:\n");
				for(i = 0; i < atoi(size); i++)
				{
					recv(clientSocket, ip, 50, 0);
					printf("%s\n", ip);
				}
				printf("%s\n", status);
			}
			
			if (0 == strcmp(buffer, "all"))
			{
				char status[50];
				recv(clientSocket, status,50,0);
				printf("%s\n",status);
			}
			
			if (0 == strcmp(buffer, "mac"))
			{
				char mac[50], status[50];
				scanf("%s", mac);
				send(clientSocket, mac, 50, 0);
				recv(clientSocket, status, 50, 0);
				char size[5];
				recv(clientSocket, size, 10, 0);
				printf("%d\n", atoi(size));
				printf("WhiteList MAC:\n");
				for (i = 0; i < atoi(size); i++)
				{
					recv(clientSocket, mac, 50, 0);
					printf("%s\n", mac);
				}
				printf("%s\n", status);
			}
		}

		else if (0 == strcmp(buffer, "update"))
		{
			scanf("%s", &buffer[0]);
			send(clientSocket, buffer, 50, 0);
			scanf("%s", &buffer[0]);
			send(clientSocket, buffer, 50, 0);
			char status[50] = "False!";
			recv(clientSocket, status, 50, 0);

			if(strcmp (0 == status, "Premiss Denied!")) 
			{
				printf("Server update: %s\n", status);
				continue;
			}
			
			for (i = 0; i < 5; ++i)
			{
				recv(clientSocket, buffer, 1024, 0);
				printf("%s", buffer);
				scanf("%s", &buffer[0]);
				send(clientSocket, buffer, strlen(buffer), 0);
			}
			printf("Server update: %s\n", status);
			struct lan _lan;
			recv(clientSocket, _lan.interface, 50, 0);
			recv(clientSocket, _lan.rule, 50, 0);
			recv(clientSocket, _lan.proto, 50, 0);
			recv(clientSocket, _lan.srcip, 50, 0);
			recv(clientSocket, _lan.srcmac, 50, 0);
			recv(clientSocket, _lan.mask, 50, 0);
			show_rule(_lan);
		}

		else if (0 == strcmp(buffer, "delete"))
		{
			scanf("%s", &buffer[0]);
			send(clientSocket, buffer, strlen(buffer), 0);
			char status[50] = "False!";
			recv(clientSocket, status, 50, 0);
			printf("Server delete: %s\n", status);
		}
		
		else
		{
			recv(clientSocket, buffer, 1024, 0);
			printf("Server:\t%s\n", buffer);
		}
	}
	return 0;
}

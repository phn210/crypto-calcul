/* FIPS 180-2 Validation tests */

#include "sha2.h"

void test(const char *vector, uint8 *digest, uint32 digest_size){
    char output[2 * SHA512_DIGEST_SIZE + 1];
    int i;

    output[2 * digest_size] = '\0';

    // Conversion du hash en chaine de caractères
    for (i = 0; i < (int) digest_size ; i++) {
       sprintf(output + 2 * i, "%02x", digest[i]);
    }

    // Affichage du hash calculé par la fonction sha256
    printf("H: %s\n", output);
    if (strcmp(vector, output)) {
        fprintf(stderr, "Test failed.\n");
        exit(EXIT_FAILURE);
    }
}

int main(void)
{
    static const char *vectors[4][3] = 
    {   /* SHA-224 */
        {
        "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7",
        "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525",
        "20794655980c91d8bbb4c1ea97618a4bf03f42581948b2ee4ee7ad67",
        },
        /* SHA-256 */
        {
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
        "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
        },
        /* SHA-384 */
        {
        "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed"
        "8086072ba1e7cc2358baeca134c825a7",
        "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712"
        "fcc7c71a557e2db966c3e9fa91746039",
        "9d0e1809716474cb086e834e310a4a1ced149e9c00f248527972cec5704c2a5b"
        "07b8b3dc38ecc4ebae97ddd87f3d8985",
        },
        /* SHA-512 */
        {
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
        "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018"
        "501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909",
        "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973eb"
        "de0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b"
        }
    };

    char message1[1000000];
    char message2a[1000000];
    /*static const char message2b[] = "abcdefghbcdefghicdefghijdefghijkefghij"
                                    "klfghijklmghijklmnhijklmnoijklmnopjklm"
                                    "nopqklmnopqrlmnopqrsmnopqrstnopqrstu";*/
    uint8 *message3;
    uint32 message3_len = 1000000;
    uint8 digest[SHA512_DIGEST_SIZE];

    message3 = malloc(message3_len);
    if (message3 == NULL) {
        fprintf(stderr, "Can't allocate memory\n");
        return -1;
    }
    
    printf("Donner un message1 :  ");
    gets(message1);
    printf("Donner un message2a :  ");
    gets(message2a);
   


   //Menu avec SWITCH
   int choix1, choix2, choix3, choix4;
   int choix;
    printf("1- SHA-224\n");
    printf("2- SHA-256\n");
    printf("3- SHA-384\n");
    printf("4- SHA-512\n");
    printf("5- Quitter\n");
    printf("Choisissez un algorithme de hashage : ");
    scanf("%d", &choix);
    switch (choix){
    case 1:
        printf("1- Message1\n");
        printf("2- Message2a\n");
       
        printf("Choisissez un message : ");
        scanf("%d", &choix1);
        if(choix1 == 1){
            printf("Hachage du message1 :  ");
            sha224((uint8 *)message1, 0, digest); printf("\n");
            printf("Test message1 : ");
            test(vectors[0][0], digest, SHA224_DIGEST_SIZE);
        }
        if(choix1 == 2){
            printf("Hachage du message2a :  ");
            sha224((uint8 *)message2a, strlen(message2a), digest); printf("\n");
            printf("Test message2a : ");
            test(vectors[0][1], digest, SHA224_DIGEST_SIZE);
        }
        break;
    case 2:
        printf("1- Message1\n");
        printf("2- Message2a\n");
        printf("Choisissez un message : ");
        scanf("%d", &choix2);
        if(choix2 == 1){
            printf("Hachage du message1 :  ");
            sha256((uint8 *)message1, 0, digest); printf("\n");
            printf("Test message1 : ");
            test(vectors[1][0], digest, SHA256_DIGEST_SIZE); printf("\n");
        }
        if(choix2 == 2){
            printf("Hachage du message2a :  ");
            sha256((uint8 *)message2a, strlen(message2a), digest); printf("\n");
            printf("Test message2a : ");
            test(vectors[1][1], digest, SHA256_DIGEST_SIZE); printf("\n");
        }
        break;  
    case 3: 
        printf("1- Message1\n");
        printf("2- Message2a\n");
        printf("Choisissez un message : ");
        scanf("%d", &choix3);
        if(choix3 == 1){
            printf("Hachage du message1 :  ");
            sha384((uint8 *)message1, 0, digest); printf("\n");
            printf("Test message1 : ");
            test(vectors[2][0], digest, SHA384_DIGEST_SIZE); printf("\n");
        }
        if(choix3 == 2){
            printf("Hachage du message2a :  ");
            sha384((uint8 *)message2a, strlen(message2a), digest);
            
            printf("Test message2a : ");
            test(vectors[2][1], digest, SHA384_DIGEST_SIZE); printf("\n");
        }

        break;
    case 4:
        printf("1- Message1\n");
        printf("2- Message2a\n");
        printf("Choisissez un message : ");
        scanf("%d", &choix4);
        if(choix4 == 1){
            printf("Hachage du message1 :  ");
            sha512((uint8 *)message1, 0, digest); printf("\n");
            printf("Test message1 : ");
            test(vectors[3][0], digest, SHA512_DIGEST_SIZE);
        }
        if(choix4 == 2){
            printf("Hachage du message2a :  ");
            sha512((uint8 *)message2a, strlen(message2a), digest); printf("\n");
            printf("Test message2a : ");
            test(vectors[3][1], digest, SHA512_DIGEST_SIZE);
        }
        break;
    case 5:
        break;
    default:
        printf("Choix invalide\n");
        break;
    }

    return 0;
}
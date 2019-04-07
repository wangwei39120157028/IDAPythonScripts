
/* vul_prog.c */

#define SECRET1 0x44

#define SECRET2 0x55

int
main(int
argc, char
*argv[])

{

  char
user_input[100];

  int
*secret;

  long
int_input;

  secret = (int
*) malloc(2*sizeof(int));

  /* getting the secret */

  secret[0] = SECRET1; secret[1] = SECRET2;

  printf("The variable secret's address is 0x%8x (on stack)\n", &secret);

  printf("The variable secret's value is 0x%8x (on heap)\n", secret);

  printf("secret[0]'s address is 0x%8x (on heap)\n", &secret[0]);

  printf("secret[1]'s address is 0x%8x (on heap)\n", &secret[1]);

  printf("Please enter a decimal integer\n");

  scanf("%d", &int_input);  /* getting an input from user */

  printf("Please enter a string\n");

  scanf("%s", user_input); /* getting a string from user */

  /* Vulnerable place */

  printf(user_input);

  printf("\n");

  /* Verify whether your attack is successful */

  printf("The original secrets: 0x%x -- 0x%x\n", SECRET1, SECRET2);

  printf("The new secrets:      0x%x -- 0x%x\n", secret[0], secret[1]);

  return
0;

}

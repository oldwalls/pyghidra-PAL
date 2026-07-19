/* WARNING: Removing unreachable block (ram,0x0010121f) */
/* WARNING: Unknown calling convention -- yet parameter storage is locked */

int main(void)

{
  int iVar1;
  uint uVar2;
  int alpha;
  int beta;
  int gamma;
  int counter;
  int i;
  int temp;
  
  alpha = 0x10;
  beta = 0x20;
  gamma = 0;
  counter = 0;
  do {
    alpha = mutate(counter + alpha);
    i = 0;
LAB_0010126f:
    if ((9 < i) || (beta < 1)) goto LAB_0010127f;
    gamma = feedback(alpha,i);
    if ((gamma ^ beta) % 3 == 0) {
      beta = beta + -2;
LAB_0010126b:
      i = i + 1;
      goto LAB_0010126f;
    }
    uVar2 = gamma & 7;
    if (uVar2 == 3) {
      do {
        if (gamma < 1) break;
        gamma = mutate(gamma >> 1);
      } while (gamma != 0xf);
    }
    else if (uVar2 < 4) {
      if (uVar2 < 2) {
        alpha = alpha ^ 0xaa;
      }
      else if (uVar2 != 2) goto LAB_00101255;
      beta = beta + 5;
    }
    else {
LAB_00101255:
      alpha = alpha - beta;
    }
    if (-1 < alpha) goto LAB_0010126b;
    alpha = 0;
LAB_0010127f:
    iVar1 = alpha;
    if ((counter & 1U) != 0) {
      alpha = beta;
      beta = iVar1;
    }
    counter = counter + 1;
    if ((4 < counter) && (99 < alpha)) {
      printf("Final: %d, %d, %d\n",(ulong)(uint)alpha,(ulong)(uint)beta,(ulong)(uint)gamma);
      return beta + alpha;
    }
  } while( true );
}

int main(void)

{
  uint uVar1;
  int iVar2;
  int acc;
  int state;
  int i;
  int j;
  int k;
  int limit;
  int outer_val;
  int alt;
  int inner_val;
  
  acc = 100;
  state = 0;
  i = 0;
  do {
    if (4 < i) {
      printf("Final State: %d, Acc: %d\n",(ulong)(uint)state,(ulong)(uint)acc);
      return acc;
    }
    uVar1 = transform_a(acc + i);
    if (((uVar1 & 1) == 0) || ((1 < i && ((int)uVar1 < 500)))) {
      for (j = 0; j < 3; j = j + 1) {
        uVar1 = transform_b(i + j);
        iVar2 = (int)uVar1 % 4;
        if (iVar2 == 2) {
          if (acc < 0xc9) {
            acc = acc + 0x32;
          }
          else {
            acc = acc + -0x14;
          }
        }
        else if (iVar2 < 3) {
          if (iVar2 == 0) {
            acc = acc + (uVar1 ^ 0x12);
          }
          else {
            if (iVar2 != 1) goto LAB_0010128d;
            iVar2 = check_bit(acc,3);
            if (iVar2 == 0) {
              acc = transform_a(acc);
            }
            else {
              acc = acc + -5;
            }
          }
        }
        else {
LAB_0010128d:
          acc = acc << 1;
        }
      }
    }
    else {
      if ((i & 1U) == 0) {
        iVar2 = transform_b(acc);
      }
      else {
        iVar2 = transform_a(i);
      }
      for (k = 0; k < 2; k = k + 1) {
        if ((iVar2 >> ((byte)k & 0x1f) & 1U) == 0) {
          acc = acc + (iVar2 >> 2);
        }
        else {
          acc = acc ^ 0xff;
        }
      }
    }
    state = (state + acc) % 10;
    if (state == 7) {
      acc = acc + -100;
    }
    i = i + 1;
  } while( true );
}

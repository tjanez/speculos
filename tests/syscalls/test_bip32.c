#include <err.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#include <cmocka.h>

#include "bolos/cx_ec.h"
#include "bolos/os_bip32.h"
#include "emulate.h"
#include "utils.h"

#define MAX_CHAIN_LEN 5

typedef struct {
  uint32_t index;
  const char *chain_code;
  const char *private_key;
} bip32_chain_vector;

typedef struct {
  cx_curve_t curve;
  const char *seed;
  /* expand_seed_bip32() doesn't compute the chain code */
  const char *chain_code;
  const char *private_key;
  int chain_len;
  const bip32_chain_vector chain[MAX_CHAIN_LEN];
} bip32_test_vector;

/* SLIP-0010's seed for Test vector 2 for ed25519
 *
 * https://github.com/satoshilabs/slips/blob/master/slip-0010.md#test-vector-2-for-ed25519
*/
static const char *default_seed =
    "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a2"
    "9f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542";

/* clang-format off */
static const bip32_test_vector test_vectors[] = {
  // Test vector 1 for secp256k1
  {
    .curve = CX_CURVE_256K1,
    .seed = "000102030405060708090a0b0c0d0e0f",
    .chain_code = "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508",
    .private_key = "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35",
    .chain_len = 5,
    .chain = {
      {0x80000000, "47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141", "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea"},
      {0x00000001, "2a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c19", "3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368"},
      {0x80000002, "04466b9cc8e161e966409ca52986c584f07e9dc81f735db683c3ff6ec7b1503f", "cbce0d719ecf7431d88e6a89fa1483e02e35092af60c042b1df2ff59fa424dca"},
      {0x00000002, "cfb71883f01676f587d023cc53a35bc7f88f724b1f8c2892ac1275ac822a3edd", "0f479245fb19a38a1954c5c7c0ebab2f9bdfd96a17563ef28a6a4b1a2a764ef4"},
      {1000000000, "c783e67b921d2beb8f6b389cc646d7263b4145701dadd2161548a8b078e65e9e", "471b76e389e528d6de6d816857e012c5455051cad6660850e58372a6c3e6e7c8"}
    }
  },
  // Test vector 1 for nist256p1
  {
    .curve = CX_CURVE_256R1,
    .seed = "000102030405060708090a0b0c0d0e0f",
    .chain_code = "beeb672fe4621673f722f38529c07392fecaa61015c80c34f29ce8b41b3cb6ea",
    .private_key = "612091aaa12e22dd2abef664f8a01a82cae99ad7441b7ef8110424915c268bc2",
    .chain_len = 5,
    .chain = {
      {0x80000000, "3460cea53e6a6bb5fb391eeef3237ffd8724bf0a40e94943c98b83825342ee11", "6939694369114c67917a182c59ddb8cafc3004e63ca5d3b84403ba8613debc0c"},
      {0x00000001, "4187afff1aafa8445010097fb99d23aee9f599450c7bd140b6826ac22ba21d0c", "284e9d38d07d21e4e281b645089a94f4cf5a5a81369acf151a1c3a57f18b2129"},
      {0x80000002, "98c7514f562e64e74170cc3cf304ee1ce54d6b6da4f880f313e8204c2a185318", "694596e8a54f252c960eb771a3c41e7e32496d03b954aeb90f61635b8e092aa7"},
      {0x00000002, "ba96f776a5c3907d7fd48bde5620ee374d4acfd540378476019eab70790c63a0", "5996c37fd3dd2679039b23ed6f70b506c6b56b3cb5e424681fb0fa64caf82aaa"},
      {1000000000, "b9b7b82d326bb9cb5b5b121066feea4eb93d5241103c9e7a18aad40f1dde8059", "21c4f269ef0a5fd1badf47eeacebeeaa3de22eb8e5b0adcd0f27dd99d34d0119"}
    }
  },
  // Test vector 2 for secp256k1
  {
    .curve = CX_CURVE_SECP256K1,
    .seed = "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
    .chain_code = "60499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd9689",
    .private_key = "4b03d6fc340455b363f51020ad3ecca4f0850280cf436c70c727923f6db46c3e",
    .chain_len = 5,
    .chain = {
          {0x00000000, "f0909affaa7ee7abe5dd4e100598d4dc53cd709d5a5c2cac40e7412f232f7c9c", "abe74a98f6c7eabee0428f53798f0ab8aa1bd37873999041703c742f15ac7e1e"},
          {0xffffffff, "be17a268474a6bb9c61e1d720cf6215e2a88c5406c4aee7b38547f585c9a37d9", "877c779ad9687164e9c2f4f0f4ff0340814392330693ce95a58fe18fd52e6e93"},
          {0x00000001, "f366f48f1ea9f2d1d3fe958c95ca84ea18e4c4ddb9366c336c927eb246fb38cb", "704addf544a06e5ee4bea37098463c23613da32020d604506da8c0518e1da4b7"},
          {0xfffffffe, "637807030d55d01f9a0cb3a7839515d796bd07706386a6eddf06cc29a65a0e29", "f1c7c871a54a804afe328b4c83a1c33b8e5ff48f5087273f04efa83b247d6a2d"},
          {0x00000002, "9452b549be8cea3ecb7a84bec10dcfd94afe4d129ebfd3b3cb58eedf394ed271", "bb7d39bdb83ecf58f2fd82b6d918341cbef428661ef01ab97c28a4842125ac23"}
      }
  },
  // Test vector 2 for nist256p1
  {
    .curve = CX_CURVE_SECP256R1,
    .seed = "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
    .chain_code = "96cd4465a9644e31528eda3592aa35eb39a9527769ce1855beafc1b81055e75d",
    .private_key = "eaa31c2e46ca2962227cf21d73a7ef0ce8b31c756897521eb6c7b39796633357",
    .chain_len = 5,
    .chain = {
      {0x00000000, "84e9c258bb8557a40e0d041115b376dd55eda99c0042ce29e81ebe4efed9b86a", "d7d065f63a62624888500cdb4f88b6d59c2927fee9e6d0cdff9cad555884df6e"},
      {0xffffffff, "f235b2bc5c04606ca9c30027a84f353acf4e4683edbd11f635d0dcc1cd106ea6", "96d2ec9316746a75e7793684ed01e3d51194d81a42a3276858a5b7376d4b94b9"},
      {0x00000001, "7c0b833106235e452eba79d2bdd58d4086e663bc8cc55e9773d2b5eeda313f3b", "974f9096ea6873a915910e82b29d7c338542ccde39d2064d1cc228f371542bbc"},
      {0xfffffffe, "5794e616eadaf33413aa309318a26ee0fd5163b70466de7a4512fd4b1a5c9e6a", "da29649bbfaff095cd43819eda9a7be74236539a29094cd8336b07ed8d4eff63"},
      {0x00000002, "3bfb29ee8ac4484f09db09c2079b520ea5616df7820f071a20320366fbe226a7", "bb0a77ba01cc31d77205d51d08bd313b979a71ef4de9b062f8958297e746bd67"}
    }
  },
  // Test derivation retry for nist256p1
  {
    .curve = CX_CURVE_SECP256R1,
    .seed = "000102030405060708090a0b0c0d0e0f",
    .chain_code = "beeb672fe4621673f722f38529c07392fecaa61015c80c34f29ce8b41b3cb6ea",
    .private_key = "612091aaa12e22dd2abef664f8a01a82cae99ad7441b7ef8110424915c268bc2",
    .chain_len = 2,
    .chain = {
      {0x80006fa2, "e94c8ebe30c2250a14713212f6449b20f3329105ea15b652ca5bdfc68f6c65c2", "06f0db126f023755d0b8d86d4591718a5210dd8d024e3e14b6159d63f53aa669"},
      {0x00008495, "9e87fe95031f14736774cd82f25fd885065cb7c358c1edf813c72af535e83071", "092154eed4af83e078ff9b84322015aefe5769e31270f62c3f66c33888335f3a"}
    }
  },
  // Test seed retry for nist256p1
  {
    .curve = CX_CURVE_SECP256R1,
    .seed = "a7305bc8df8d0951f0cb224c0e95d7707cbdf2c6ce7e8d481fec69c7ff5e9446",
    .chain_code = "7762f9729fed06121fd13f326884c82f59aa95c57ac492ce8c9654e60efd130c",
    .private_key = "3b8c18469a4634517d6d0b65448f8e6c62091b45540a1743c5846be55d47d88f",
    .chain_len = 0,
    .chain = {}
  },
};
/* clang-format on */

struct bolos_vector {
  int mode;
  int curve;
  const char *path;
  const char *seed_key;
  const char *chain;
  const char *key;
};

/* clang-format off */
static const struct bolos_vector bolos_vectors[] = {
  /* SLIP-0010's Test vector 2 for ed25519
   *
   * https://github.com/satoshilabs/slips/blob/master/slip-0010.md#test-vector-2-for-ed25519
   */
    {
    .mode = 1,
    .curve = 2,
    .path = "",
    .seed_key = "",
    .chain = "ef70a74db9c3a5af931b5fe73ed8e1a53464133654fd55e7a66f8570b8e33c3b",
    .key = "171cb88b1b3c1db25add599712e36245d75bc65a1a5c9e18d76f9f2b1eab40120000000000000000000000000000000000000000000000000000000000000000"
  },
    {
    .mode = 1,
    .curve = 2,
    .path = "0'",
    .seed_key = "",
    .chain = "0b78a3226f915c082bf118f83618a618ab6dec793752624cbeb622acb562862d",
    .key = "1559eb2bbec5790b0c65d8693e4d0875b1747f4970ae8b650486ed74708456350000000000000000000000000000000000000000000000000000000000000000"
  },
    {
    .mode = 1,
    .curve = 2,
    .path = "0'/2147483647'",
    .seed_key = "",
    .chain = "138f0b2551bcafeca6ff2aa88ba8ed0ed8de070841f0c4ef0165df8181eaad7f",
    .key = "ea4f5bfe8694d8bb74b7b59404632fd5968b774ed545e810de9c32a4fb4192f40000000000000000000000000000000000000000000000000000000000000000"
  },
    {
    .mode = 1,
    .curve = 2,
    .path = "0'/2147483647'/1'",
    .seed_key = "",
    .chain = "73bd9fff1cfbde33a1b846c27085f711c0fe2d66fd32e139d3ebc28e5a4a6b90",
    .key = "3757c7577170179c7868353ada796c839135b3d30554bbb74a4b1e4a5a58505c0000000000000000000000000000000000000000000000000000000000000000"
  },
    {
    .mode = 1,
    .curve = 2,
    .path = "0'/2147483647'/1'/2147483646'",
    .seed_key = "",
    .chain = "0902fe8a29f9140480a00ef244bd183e8a13288e4412d8389d140aac1794825a",
    .key = "5837736c89570de861ebc173b1086da4f505d4adb387c6a1b1342d5e4ac9ec720000000000000000000000000000000000000000000000000000000000000000"
  },
  {
    .mode = 1,
    .curve = 2,
    .path = "0'/2147483647'/1'/2147483646'/2'",
    .seed_key = "",
    .chain = "5d70af781f3a37b829f0d060924d5e960bdc02e85423494afc0b1a41bbe196d4",
    .key = "551d333177df541ad876a60ea71f00447931c0a9da16f227c11ea080d7391b8d0000000000000000000000000000000000000000000000000000000000000000"
  },

};
/* clang-format on */

/* https://github.com/satoshilabs/slips/blob/master/slip-0010.md#test-vector-1-for-ed25519
 */
/* clang-format off */
static const struct bolos_vector slip10_vectors[] = {
  {
    .mode = 1,
    .curve = 2,
    .path = "",
    .seed_key = "",
    .chain = "90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb",
    .key = "2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e70000000000000000000000000000000000000000000000000000000000000000"
  },
  {
    .mode = 1,
    .curve = 2,
    .path = "0'",
    .seed_key = "",
    .chain = "8b59aa11380b624e81507a27fedda59fea6d0b779a778918a2fd3590e16e9c69",
    .key = "68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a30000000000000000000000000000000000000000000000000000000000000000"
  },
  {
    .mode = 1,
    .curve = 2,
    .path = "0'/1'",
    .seed_key = "",
    .chain = "a320425f77d1b5c2505a6b1b27382b37368ee640e3557c315416801243552f14",
    .key = "b1d0bad404bf35da785a64ca1ac54b2617211d2777696fbffaf208f746ae84f20000000000000000000000000000000000000000000000000000000000000000"
  },
  {
    .mode = 1,
    .curve = 2,
    .path = "0'/1'/2'",
    .seed_key = "",
    .chain = "2e69929e00b5ab250f49c3fb1c12f252de4fed2c1db88387094a0f8c4c9ccd6c",
    .key = "92a5b23c0b8a99e37d07df3fb9966917f5d06e02ddbd909c7e184371463e9fc90000000000000000000000000000000000000000000000000000000000000000"
  },
  {
    .mode = 1,
    .curve = 2,
    .path = "0'/1'/2'/2'",
    .seed_key = "",
    .chain = "8f6d87f93d750e0efccda017d662a1b31a266e4a6f5993b15f5c1f07f74dd5cc",
    .key = "30d1dc7e5fc04c31219ab25a27ae00b50f6fd66622f6e9c913253d6511d1e6620000000000000000000000000000000000000000000000000000000000000000"
  },
  {
    .mode = 1,
    .curve = 2,
    .path = "0'/1'/2'/2'/1000000000'",
    .seed_key = "",
    .chain = "68789923a0cac2cd5a29172a475fe9e0fb14cd6adb5ad98a3fa70333e7afa230",
    .key = "8f94d394a8e8fd6b1bc2f3f49f5c47e385281d5c17e65324b0f62483e37e87930000000000000000000000000000000000000000000000000000000000000000"
  }
};
/* clang-format on */

static void test_bip32_vector(const bip32_test_vector *v)
{
  uint8_t expected_key[32], key[32], expected_chain_code[32], chain_code[32];
  unsigned int path[MAX_CHAIN_LEN];
  extended_private_key extkey;
  int i, path_len;

  memset(&extkey, 0, sizeof(extkey));

  assert_int_equal(setenv("SPECULOS_SEED", v->seed, 1), 0);

  for (i = 0; i < v->chain_len; i++) {
    path[i] = v->chain[i].index;
    path_len = i + 1;

    sys_os_perso_derive_node_bip32(v->curve, path, path_len, key, chain_code);

    assert_int_equal(
        hexstr2bin(v->chain[i].private_key, expected_key, sizeof(expected_key)),
        sizeof(expected_key));
    assert_int_equal(hexstr2bin(v->chain[i].chain_code, expected_chain_code,
                                sizeof(expected_chain_code)),
                     sizeof(expected_chain_code));
    assert_memory_equal(key, expected_key, sizeof(expected_key));
    assert_memory_equal(chain_code, expected_chain_code, sizeof(chain_code));
  }
}

static void test_bip32(void **state __attribute__((unused)))
{
  size_t i;

  for (i = 0; i < ARRAY_SIZE(test_vectors); i++) {
    test_bip32_vector(&test_vectors[i]);
  }
}

static int get_bip32_path(const char *str_, unsigned int *path,
                          int max_path_len)
{
  char *token, *str;
  int path_len;
  size_t len;

  str = strdup(str_);
  if (str == NULL) {
    warn("strdup");
    return -1;
  }

  path_len = 0;
  while (1) {
    token = strtok((path_len == 0) ? str : NULL, "/");
    if (token == NULL) {
      break;
    }

    if (path_len >= max_path_len) {
      return -1;
    }

    len = strlen(token);
    if (len == 0) {
      return -1;
    }

    if (token[len - 1] == '\'') {
      token[len - 1] = '\x00';
      path[path_len] = 0x80000000;
    } else {
      path[path_len] = 0;
    }

    path[path_len] |= strtoul(token, NULL, 10);

    path_len += 1;
  }

  free(str);

  return path_len;
}

static void test_bolos_vector(const struct bolos_vector *v)
{
  uint8_t expected_key[64], key[64], expected_chain[32], chain[32];
  uint32_t path[MAX_CHAIN_LEN];
  unsigned int mode;
  cx_curve_t curve;
  size_t sk_length;
  ssize_t path_len;
  uint8_t *p;

  switch (v->mode) {
  case 0:
    mode = HDW_NORMAL;
    break;
  case 1:
    mode = HDW_ED25519_SLIP10;
    break;
  case 2:
    mode = HDW_SLIP21;
    break;
  default:
    fail();
    break;
  }

  switch (v->curve) {
  case 0:
    curve = CX_CURVE_SECP256R1;
    break;
  case 1:
    curve = CX_CURVE_SECP256K1;
    break;
  case 2:
    curve = CX_CURVE_Ed25519;
    break;
  default:
    fail();
    break;
  }

  if (mode == HDW_SLIP21) {
    path_len = 1 + strlen(v->path);
    assert_true((size_t)path_len < sizeof(path));
    p = (uint8_t *)path;
    p[0] = '\x00';
    memcpy(p + 1, v->path, path_len - 1);
  } else {
    path_len = get_bip32_path(v->path, path, MAX_CHAIN_LEN);
    assert_true(path_len >= 0);
  }

  sk_length = strlen(v->seed_key);

  memset(chain, 0, sizeof(chain));
  memset(key, 0, sizeof(key));

  sys_os_perso_derive_node_with_seed_key(mode, curve, path, path_len, key,
                                         chain, (uint8_t *)v->seed_key,
                                         sk_length);

  assert_int_equal(hexstr2bin(v->key, expected_key, sizeof(expected_key)),
                   sizeof(expected_key));
  assert_int_equal(hexstr2bin(v->chain, expected_chain, sizeof(expected_chain)),
                   sizeof(expected_chain));

  unsigned int i;
  fprintf(stderr, "expected_key: ");
  for (i = 0; i < 64; i++) {
    fprintf(stderr, "%02x", expected_key[i]);
  }
  fprintf(stderr, "\n");
  fprintf(stderr, "actual_key: ");
  for (i = 0; i < 64; i++) {
    fprintf(stderr, "%02x", key[i]);
  }
  fprintf(stderr, "\n");

  assert_memory_equal(key, expected_key, sizeof(expected_key));
  assert_memory_equal(chain, expected_chain, sizeof(chain));
}

static void test_derive(void **state __attribute__((unused)))
{
  unsigned int i;

  assert_int_equal(setenv("SPECULOS_SEED", default_seed, 1), 0);

  for (i = 0; i < ARRAY_SIZE(bolos_vectors); i++) {
    test_bolos_vector(&bolos_vectors[i]);
  }

  assert_int_equal(
      setenv("SPECULOS_SEED", "000102030405060708090a0b0c0d0e0f", 1), 0);

  for (i = 0; i < ARRAY_SIZE(slip10_vectors); i++) {
    test_bolos_vector(&slip10_vectors[i]);
  }
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test(test_bip32),
    cmocka_unit_test(test_derive),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}

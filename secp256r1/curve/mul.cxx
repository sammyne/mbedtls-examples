#include <iostream>
#include <memory>

#include <mbedtls/bignum.h>
#include <mbedtls/ecp.h>

using namespace std;

using std::shared_ptr;

string hexlify(uint8_t buf[65])
{
  const auto alphabet = "0123456789abcdef";

  string out;
  for (auto i = 0; i < 65; i++)
  {
    out += alphabet[buf[i] >> 4];
    out += alphabet[buf[i] & 0x0f];
  }

  return out;
}

string hexlify_point(const mbedtls_ecp_group *grp, const mbedtls_ecp_point *P)
{
  const auto fmt = MBEDTLS_ECP_PF_UNCOMPRESSED;
  const int ell = 65;
  size_t olen = 0;

  uint8_t buf[ell];
  auto err = mbedtls_ecp_point_write_binary(grp, P, fmt, &olen, buf, ell);
  if (err)
  {
    cout << "fail to output P in binary: " << err << endl;
    return "";
  }

  if (olen != ell)
  {
    cout << "invalid olen(" << olen << "), expect " << ell << endl;
    return "";
  }

  return hexlify(buf);
}

int main()
{
  mbedtls_ecp_point X;
  mbedtls_ecp_point_init(&X);

  const auto x = "bacd6248af878bf4678432c04e420bfe9441b6d26b432d2db94a8df38e27aa04";
  const auto y = "50b8876678dd699484ebc72eebd0881cffd088114352ac28a98466ac2466f9da";
  auto err = mbedtls_ecp_point_read_string(&X, 16, x, y);
  if (err)
  {
    mbedtls_ecp_point_free(&X);
    cout << "fail to decode X: " << err << endl;
    return -1;
  }

  mbedtls_ecp_group grp;
  mbedtls_ecp_group_init(&grp);
  err = mbedtls_ecp_group_load(&grp, mbedtls_ecp_group_id::MBEDTLS_ECP_DP_SECP256R1);
  if (err)
  {
    mbedtls_ecp_group_free(&grp);
    mbedtls_ecp_point_free(&X);
    cout << "fail to init group: " << err << endl;
    return -2;
  }

  {
    const auto expect = "04bacd6248af878bf4678432c04e420bfe9441b6d26b432d2db94a8df38e27aa0450b8876678dd699484ebc72eebd0881cffd088114352ac28a98466ac2466f9da";
    auto xHex = hexlify_point(&grp, &X);
    if (expect != xHex)
    {
      cout << "invalid X" << endl;
      cout << "expect " << expect << endl;
      cout << "   got " << xHex << endl;
    }
  }

  mbedtls_mpi k;
  mbedtls_mpi_init(&k);

  err = mbedtls_mpi_read_string(&k, 10, "123");
  if (err)
  {
    mbedtls_mpi_free(&k);
    mbedtls_ecp_group_free(&grp);
    mbedtls_ecp_point_free(&X);

    cout << "fail to set k: " << err << endl;
    return -2;
  }

  mbedtls_ecp_point kX;
  mbedtls_ecp_point_init(&kX);

  err = mbedtls_ecp_mul(&grp, &kX, &k, &X, nullptr, nullptr);
  if (err)
  {
    mbedtls_ecp_point_free(&kX);
    mbedtls_mpi_free(&k);
    mbedtls_ecp_group_free(&grp);
    mbedtls_ecp_point_free(&X);

    cout << "fail to calc k*X: " << err << endl;
    return -3;
  }

  //cout << "K: ";
  //print_point(&grp, &kX);
  {
    const auto expect = "0440b9014543b7cbb010bda769e59f95eba92a8c3ef7ea70b808f43652831840bed00af5934506e462e36a6aecc7193d34e5fa39a5cb544c73e4ad5fb8237333d2";
    auto kxHex = hexlify_point(&grp, &kX);
    if (expect != kxHex)
    {
      cout << "invalid kX" << endl;
      cout << "expect " << expect << endl;
      cout << "   got " << kxHex << endl;
    }
  }

  mbedtls_ecp_point_free(&kX);
  mbedtls_mpi_free(&k);
  mbedtls_ecp_group_free(&grp);
  mbedtls_ecp_point_free(&X);

  cout << "done" << endl;

  return 0;
}
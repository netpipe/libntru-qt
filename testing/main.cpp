#include <iostream>
#include <vector>
#include <string>
#include <map>
#include <cmath>
#include <bitset>

using namespace std;

using Poly = vector<int>;

int mod(int a, int p) {
    int r = a % p;
    return (r < 0) ? r + p : r;
}

Poly trim(const Poly &a) {
    Poly res = a;
    while (!res.empty() && res.back() == 0) res.pop_back();
    return res;
}

Poly poladd(const Poly &a, const Poly &b, int p) {
    Poly result(max(a.size(), b.size()), 0);
    for (size_t i = 0; i < a.size(); ++i) result[i] = a[i];
    for (size_t i = 0; i < b.size(); ++i) result[i] += b[i];
    for (auto &x : result) x = mod(x, p);
    return trim(result);
}

Poly polsub(const Poly &a, const Poly &b, int p) {
    Poly result(max(a.size(), b.size()), 0);
    for (size_t i = 0; i < a.size(); ++i) result[i] = a[i];
    for (size_t i = 0; i < b.size(); ++i) result[i] -= b[i];
    for (auto &x : result) x = mod(x, p);
    return trim(result);
}

Poly polmul(const Poly &a, const Poly &b, int p = 0) {
    Poly result(a.size() + b.size() - 1, 0);
    for (size_t i = 0; i < a.size(); ++i)
        for (size_t j = 0; j < b.size(); ++j)
            result[i + j] += a[i] * b[j];
    if (p != 0) for (auto &x : result) x = mod(x, p);
    return trim(result);
}

Poly poldiv(const Poly &a, const Poly &b, int p, Poly &remainder) {
    Poly dividend = a, divisor = b;
    Poly quotient(dividend.size(), 0);
    int inv_lead = mod(b.back(), p);

    while (dividend.size() >= divisor.size() && !dividend.empty()) {
        int coeff = dividend.back() * inv_lead;
        size_t diff = dividend.size() - divisor.size();
        Poly temp(diff + divisor.size(), 0);
        for (size_t i = 0; i < divisor.size(); ++i) {
            temp[i + diff] = mod(divisor[i] * coeff, p);
        }
        quotient[diff] = coeff;
        dividend = polsub(dividend, temp, p);
    }
    remainder = dividend;
    return trim(quotient);
}

Poly polEEA(const Poly &a, const Poly &b, int p) {
    Poly r0 = a, r1 = b;
    Poly s0 = {1}, s1 = {0};

    while (!r1.empty()) {
        Poly rem;
        Poly q = poldiv(r0, r1, p, rem);
        Poly s = polsub(s0, polmul(q, s1, p), p);
        r0 = r1;
        r1 = rem;
        s0 = s1;
        s1 = s;
    }
    return s0;
}

Poly inverse(const Poly &f, int n, int mod) {
    Poly xN1(n + 1, 0);
    xN1[0] = -1;
    xN1[n] = 1;
    Poly inv = polEEA(f, xN1, mod);
    return inv;
}

Poly convol(const Poly &f, const Poly &g, int n, int p = 0) {
    Poly ff = f, gg = g;
    ff.resize(n, 0);
    gg.resize(n, 0);
    Poly result(n, 0);
    for (int k = 0; k < n; ++k)
        for (int i = 0; i < n; ++i)
            result[k] += ff[i] * gg[(k - i + n) % n];
    if (p != 0)
        for (auto &x : result) x = mod(x, p);
    return result;
}

Poly string_to_polynomial(const string &message) {
    map<string, Poly> mapping = {
        {"000", {0, 0}}, {"001", {0, 1}}, {"010", {0, -1}}, {"011", {1, 0}},
        {"100", {1, 1}}, {"101", {1, -1}}, {"110", {-1, 0}}, {"111", {-1, 1}}
    };
    Poly result;
    for (size_t i = 0; i + 2 < message.size(); i += 3) {
        string block = message.substr(i, 3);
        auto coeff = mapping[block];
        result.insert(result.end(), coeff.begin(), coeff.end());
    }
    return result;
}

string text_to_binary(const string &text) {
    string binary;
    for (char c : text)
        binary += bitset<8>(c).to_string();
    while (binary.size() % 3 != 0)
        binary += "0";
    return binary;
}

Poly encrypt(int p, const Poly &phi, const Poly &pubKey, const Poly &msg, int q, int n) {
    Poly pPhi(phi.size());
    for (size_t i = 0; i < phi.size(); ++i)
        pPhi[i] = p * phi[i];
    Poly c = convol(pPhi, pubKey, n, 0);
    if (c.size() < msg.size())
        c.resize(msg.size(), 0);
    else if (msg.size() < c.size()) {
        Poly m = msg;
        m.resize(c.size(), 0);
        return encrypt(p, phi, pubKey, m, q, n);
    }
    Poly encrypted(c.size());
    for (size_t i = 0; i < c.size(); ++i)
        encrypted[i] = mod(c[i] + msg[i], q);
    return encrypted;
}

string binary_to_text(const string &binary) {
    string text;
    for (size_t i = 0; i + 7 < binary.size(); i += 8) {
        bitset<8> bits(binary.substr(i, 8));
        text += char(bits.to_ulong());
    }
    return text;
}

string polynomial_to_string(const Poly &poly) {
    map<Poly, string> reverse_map = {
        {{0, 0}, "000"}, {{0, 1}, "001"}, {{0, -1}, "010"}, {{1, 0}, "011"},
        {{1, 1}, "100"}, {{1, -1}, "101"}, {{-1, 0}, "110"}, {{-1, 1}, "111"}
    };
    string bits;
    for (size_t i = 0; i + 1 < poly.size(); i += 2) {
        Poly pair = {poly[i], poly[i + 1]};
        if (reverse_map.count(pair))
            bits += reverse_map[pair];
        else
            bits += "000"; // fallback
    }
    return bits;
}

Poly decrypt(const Poly &cipher, const Poly &f, const Poly &f_inv_p, int p, int q, int n) {
    Poly a = convol(f, cipher, n, q);
    Poly decrypted(a.size());
    for (size_t i = 0; i < a.size(); ++i)
        decrypted[i] = mod(a[i], p);
    Poly result = convol(f_inv_p, decrypted, n, p);
for (int &x : result) { //testing this for now
    if (x > p / 2) x -= p;  // general way to interpret mod-p as signed
}
    return result;
}

void print_poly(const Poly &p, const string &label) {
    cout << label << ": [ ";
    for (auto x : p) cout << x << " ";
    cout << "]\n";
}

int main() {
    int p = 3, q = 32, n = 11;
    string input = "Hi";
    string binary_msg = text_to_binary(input);
    Poly msg = string_to_polynomial(binary_msg);

    Poly pubKey = {1, 2, 0, 1, -1, 0, 2, 0, 1, -1, 0};
    Poly phi = {1, 0, -1, 0, 1, 0, -1, 0, 1, 0, -1};
    Poly f = {1, 0, 1, 0, -1, 0, 1, 0, -1, 0, 1};
    Poly f_inv_p = inverse(f, n, p);

    Poly encrypted = encrypt(p, phi, pubKey, msg, q, n);
    Poly decrypted = decrypt(encrypted, f, f_inv_p, p, q, n);
    
string recovered_bits = polynomial_to_string(decrypted);
string recovered_text = binary_to_text(recovered_bits);

cout << "Recovered text: " << recovered_text << endl;

    print_poly(msg, "Message");
    print_poly(encrypted, "Encrypted Message");
    print_poly(decrypted, "Decrypted Message");
    return 0;
}
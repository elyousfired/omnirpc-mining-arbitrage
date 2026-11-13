import json
import urllib.request

q = '{ __type(name: "Transaction") { fields { name } } }'
req = urllib.request.Request(
    "https://graphql.mainnet.sui.io/graphql",
    data=json.dumps({"query": q}).encode(),
    headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"},
)
print("Sui Transaction fields:", urllib.request.urlopen(req, timeout=10).read().decode())

q2 = """
{
  transactions(last: 30) {
    nodes {
      digest
      sender { address }
      kind {
        __typename
        ... on ProgrammableTransaction {
          commands(first: 10) {
            nodes {
              __typename
              ... on MoveCallCommand {
                function {
                  module { package { address } name }
                  name
                }
              }
            }
          }
        }
      }
    }
  }
}
"""
req2 = urllib.request.Request(
    "https://graphql.mainnet.sui.io/graphql",
    data=json.dumps({"query": q2}).encode(),
    headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"},
)
print("Sui live txs:", urllib.request.urlopen(req2, timeout=10).read().decode()[:600])


def sol_rpc(m, p):
    r = urllib.request.Request(
        "https://api.mainnet-beta.solana.com",
        data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": m, "params": p}).encode(),
        headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"},
    )
    return json.loads(urllib.request.urlopen(r, timeout=15).read().decode())


slot = sol_rpc("getSlot", [{"commitment": "confirmed"}])["result"]
blks = sol_rpc("getBlocks", [slot - 5, slot, {"commitment": "confirmed"}])["result"]
b = sol_rpc("getBlock", [blks[-1], {"encoding": "json", "transactionDetails": "full", "rewards": False, "maxSupportedTransactionVersion": 1}])
print("Solana block", blks[-1], "txs:", len((b.get("result") or {}).get("transactions") or []), "err:", b.get("error"))

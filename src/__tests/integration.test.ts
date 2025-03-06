/**
 * tests/AuthFetch.test.ts
 */
import fs from 'fs'
import path from 'path'
import {
  CompletedProtoWallet,
  MasterCertificate,
  PrivateKey,
  RequestedCertificateTypeIDAndFieldList,
  Utils,
  VerifiableCertificate,
  AuthFetch
} from '@bsv/sdk'
import { Server } from 'http'
import { startServer } from './testExpressServer'
import { MockWallet } from './MockWallet'

export interface RequestedCertificateSet {
  certifiers: string[]
  types: RequestedCertificateTypeIDAndFieldList
}

describe('AuthFetch and AuthExpress Integration Tests', () => {
  const privKey = PrivateKey.fromRandom()
  let server: Server
  beforeAll((done) => {
    // Start the Express server
    server = startServer(3000)
    server.on('listening', () => {
      console.log('Test server is running on http://localhost:3000')
      done()
    })
  })

  afterAll((done) => {
    // Close the server after tests
    server.close(() => {
      console.log('Test server stopped')
      done()
    })
  })

  // --------------------------------------------------------------------------
  // Main Tests
  // --------------------------------------------------------------------------

  test('Test 1: Simple POST request with JSON', async () => {
    const walletWithRequests = new MockWallet(privKey)
    const authFetch = new AuthFetch(walletWithRequests)
    const result = await authFetch.fetch(
      'http://localhost:3000/other-endpoint',
      {
        method: 'POST',
        headers: {
          'content-type': 'application/json'
        },
        body: JSON.stringify({ message: 'Hello from JSON!' })
      }
    )
    expect(result.status).toBe(200)
    const jsonResponse = await result.json()
    console.log(jsonResponse)
    expect(jsonResponse).toBeDefined()
  }, 1500000)

  test('Test 2: POST request with URL-encoded data', async () => {
    const walletWithRequests = new CompletedProtoWallet(privKey)
    const authFetch = new AuthFetch(walletWithRequests)
    const result = await authFetch.fetch(
      'http://localhost:3000/other-endpoint',
      {
        method: 'POST',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          'x-bsv-test': 'this is a test header',
        },
        body: new URLSearchParams({ message: 'hello!', type: 'form-data' }).toString(),
      }
    )
    expect(result.status).toBe(200)
    const textResponse = await result.text()
    expect(textResponse).toBeDefined()
  })

  test('Test 3: POST request with plain text', async () => {
    const walletWithRequests = new CompletedProtoWallet(privKey)
    const authFetch = new AuthFetch(walletWithRequests)
    const result = await authFetch.fetch(
      'http://localhost:3000/other-endpoint',
      {
        method: 'POST',
        headers: {
          'content-type': 'text/plain',
          'x-bsv-test': 'this is a test header',
        },
        body: 'Hello, this is a plain text message!',
      }
    )
    expect(result.status).toBe(200)
    const textResponse = await result.text()
    expect(textResponse).toBeDefined()
  })

  test('Test 4: POST request with binary data', async () => {
    const walletWithRequests = new CompletedProtoWallet(privKey)
    const authFetch = new AuthFetch(walletWithRequests)
    const result = await authFetch.fetch(
      'http://localhost:3000/other-endpoint',
      {
        method: 'POST',
        headers: {
          'content-type': 'application/octet-stream',
          'x-bsv-test': 'this is a test header',
        },
        body: Utils.toArray('Hello from binary!'),
      }
    )
    expect(result.status).toBe(200)
    const textResponse = await result.text()
    expect(textResponse).toBeDefined()
  })

  test('Test 5: Simple GET request', async () => {
    const walletWithRequests = new CompletedProtoWallet(privKey)
    const authFetch = new AuthFetch(walletWithRequests)
    const result = await authFetch.fetch('http://localhost:3000/')
    expect(result.status).toBe(200)
    const textResponse = await result.text()
    expect(textResponse).toBeDefined()
  })

  // TODO: Requires modifying the test server to support this.
  // test('Test 6: Fetch and save video', async () => {
  //   const walletWithRequests = new CompletedProtoWallet(privKey)
  //   const authFetch = new AuthFetch(walletWithRequests)
  //   const videoResponse = await authFetch.fetch('http://localhost:3000/video')
  //   expect(videoResponse.status).toBe(200)
  //   const arrayBuffer = await videoResponse.arrayBuffer()
  //   const buffer = Buffer.from(arrayBuffer)
  //   const outputPath = path.join(__dirname, 'downloaded_video.mp4')
  //   fs.writeFileSync(outputPath, buffer)
  //   expect(fs.existsSync(outputPath)).toBe(true)
  //   const stats = fs.statSync(outputPath)
  //   expect(stats.size).toBeGreaterThan(0)
  // })

  test('Test 7: PUT request with JSON', async () => {
    const walletWithRequests = new CompletedProtoWallet(privKey)
    const authFetch = new AuthFetch(walletWithRequests)
    const result = await authFetch.fetch(
      'http://localhost:3000/put-endpoint',
      {
        method: 'PUT',
        headers: {
          'content-type': 'application/json',
          'x-bsv-test': 'this is a test header',
        },
        body: JSON.stringify({ key: 'value', action: 'update' }),
      }
    )
    expect(result.status).toBe(200)
    const textResponse = await result.text()
    expect(textResponse).toBeDefined()
  })

  test('Test 8: DELETE request', async () => {
    const walletWithRequests = new CompletedProtoWallet(privKey)
    const authFetch = new AuthFetch(walletWithRequests)
    const result = await authFetch.fetch(
      'http://localhost:3000/delete-endpoint',
      {
        method: 'DELETE',
        headers: {
          'x-bsv-test': 'this is a test header',
        }
      }
    )
    expect(result.status).toBe(200)
    const textResponse = await result.text()
    expect(textResponse).toBeDefined()
  })

  test('Test 9: Large binary upload', async () => {
    const walletWithRequests = new CompletedProtoWallet(privKey)
    const authFetch = new AuthFetch(walletWithRequests)
    const largeBuffer = Utils.toArray('Hello from a large upload test')
    const result = await authFetch.fetch('http://localhost:3000/large-upload', {
      method: 'POST',
      headers: {
        'content-type': 'application/octet-stream',
      },
      body: largeBuffer
    })
    expect(result.status).toBe(200)
    const textResponse = await result.text()
    expect(textResponse).toBeDefined()
  })

  test('Test 10: Query parameters', async () => {
    const walletWithRequests = new CompletedProtoWallet(privKey)
    const authFetch = new AuthFetch(walletWithRequests)
    const result = await authFetch.fetch(
      'http://localhost:3000/query-endpoint?param1=value1&param2=value2'
    )
    expect(result.status).toBe(200)
    const textResponse = await result.text()
    expect(textResponse).toBeDefined()
  })

  test('Test 11: Custom headers', async () => {
    const walletWithRequests = new CompletedProtoWallet(privKey)
    const authFetch = new AuthFetch(walletWithRequests)
    const result = await authFetch.fetch('http://localhost:3000/custom-headers', {
      method: 'GET',
      headers: {
        'x-bsv-custom-header': 'CustomHeaderValue',
      }
    })
    expect(result.status).toBe(200)
    const textResponse = await result.text()
    expect(textResponse).toBeDefined()
  })

  // test('Test 12: Certificate request', async () => {
  //   const requestedCertificates: RequestedCertificateSet = {
  //     certifiers: [
  //       '03caa1baafa05ecbf1a5b310a7a0b00bc1633f56267d9f67b1fd6bb23b3ef1abfa',
  //     ],
  //     types: {
  //       'z40BOInXkI8m7f/wBrv4MJ09bZfzZbTj2fJqCtONqCY=': ['firstName'],
  //     }
  //   }
  //   const walletWithRequests = new MockWallet(privKey)
  //   const certifierPrivateKey = PrivateKey.fromHex(
  //     '5a4d867377bd44eba1cecd0806c16f24e293f7e218c162b1177571edaeeaecef'
  //   )
  //   const certifierWallet = new CompletedProtoWallet(certifierPrivateKey)
  //   const certificateType = 'z40BOInXkI8m7f/wBrv4MJ09bZfzZbTj2fJqCtONqCY='
  //   const certificateSerialNumber = Utils.toBase64(new Array(32).fill(2))
  //   const fields = { firstName: 'Alice', lastName: 'Doe' }
  //   const masterCert = await MasterCertificate.issueCertificateForSubject(
  //     certifierWallet,
  //     (await walletWithRequests.getPublicKey({ identityKey: true })).publicKey,
  //     fields,
  //     certificateType,
  //     undefined,
  //     certificateSerialNumber
  //   )

  //   walletWithRequests.addMasterCertificate(masterCert)
  //   const authWithCerts = new AuthFetch(walletWithRequests)
  //   const certRequests = [
  //     authWithCerts.sendCertificateRequest(
  //       'http://localhost:3000',
  //       requestedCertificates
  //     ),
  //     authWithCerts.sendCertificateRequest(
  //       'http://localhost:3000',
  //       requestedCertificates
  //     )
  //   ]
  //   const certs = await Promise.all(certRequests)
  //   expect(certs).toBeDefined()
  //   expect(certs.length).toBe(2)
  //   // Add further assertions based on expected certificates
  // }, 15000)

  // // NOTE: YOU MUST MODIFY THE SERVER SIDE TO REQUEST CERTIFICATES FOR THIS TEST TO PASS:
  // test('Test 13: Simple GET request with certificate requests', async () => {
  //   const requestedCertificates: RequestedCertificateSet = {
  //     certifiers: [
  //       '03caa1baafa05ecbf1a5b310a7a0b00bc1633f56267d9f67b1fd6bb23b3ef1abfa'
  //     ],
  //     types: {
  //       'z40BOInXkI8m7f/wBrv4MJ09bZfzZbTj2fJqCtONqCY=': ['firstName']
  //     }
  //   }
  //   const walletWithRequests = new MockWallet(privKey)
  //   const certifierPrivateKey = PrivateKey.fromHex(
  //     '5a4d867377bd44eba1cecd0806c16f24e293f7e218c162b1177571edaeeaecef'
  //   )
  //   const certifierWallet = new CompletedProtoWallet(certifierPrivateKey)
  //   const certificateType = 'z40BOInXkI8m7f/wBrv4MJ09bZfzZbTj2fJqCtONqCY='
  //   const fields = { firstName: 'Alice', lastName: 'Doe' }
  //   const masterCert = await MasterCertificate.issueCertificateForSubject(
  //     certifierWallet,
  //     (await walletWithRequests.getPublicKey({ identityKey: true })).publicKey,
  //     fields,
  //     certificateType
  //   )
  //   walletWithRequests.addMasterCertificate(masterCert)
  //   const authFetchWithRequests = new AuthFetch(
  //     walletWithRequests,
  //     requestedCertificates
  //   )
  //   const result = await authFetchWithRequests.fetch('http://localhost:3000/')
  //   expect(result.status).toBe(200)
  //   const responseText = await result.text()
  //   expect(responseText).toBeDefined()
  //   const certs = authFetchWithRequests.consumeReceivedCertificates()
  //   expect(certs).toBeDefined()
  //   if (certs.length === 0) {
  //     console.log('No certificates received.')
  //   } else {
  //     const cert = certs[0]

  //     const verifiableCertificate = new VerifiableCertificate(
  //       cert.type,
  //       cert.serialNumber,
  //       cert.subject,
  //       cert.certifier,
  //       cert.revocationOutpoint,
  //       cert.fields,
  //       cert.keyring,
  //       cert.signature
  //     )

  //     const decryptedFields = await verifiableCertificate.decryptFields(walletWithRequests)
  //     console.log(decryptedFields)
  //     expect(Object.keys(cert.keyring) === Object.keys(decryptedFields))
  //   }
  // }, 300000)

  // --------------------------------------------------------------------------
  // Edge-Case Tests
  // --------------------------------------------------------------------------

  test('Edge Case A: No Content-Type', async () => {
    const walletWithRequests = new CompletedProtoWallet(privKey)
    const authFetch = new AuthFetch(walletWithRequests)
    await expect(
      authFetch.fetch('http://localhost:3000/no-content-type-endpoint', {
        method: 'POST',
        // Intentionally no 'content-type' header
        body: 'This should fail if your code requires Content-Type for POST.',
      })
    ).rejects.toThrow()
  })

  test('Edge Case B: application json content with undefined body', async () => {
    const walletWithRequests = new MockWallet(privKey)
    const authFetch = new AuthFetch(walletWithRequests)
    const result = await authFetch.fetch(
      'http://localhost:3000/other-endpoint',
      {
        method: 'POST',
        headers: {
          'content-type': 'application/json'
        },
        body: undefined
      }
    )
    expect(result.status).toBe(200)
    const jsonResponse = await result.json()
    console.log(jsonResponse)
    expect(jsonResponse).toBeDefined()
  }, 1500000)

  test('Edge Case C: application json content with body of type object', async () => {
    const walletWithRequests = new MockWallet(privKey)
    const authFetch = new AuthFetch(walletWithRequests)
    const result = await authFetch.fetch(
      'http://localhost:3000/other-endpoint',
      {
        method: 'POST',
        headers: {
          'content-type': 'application/json'
        },
        body: {}
      }
    )
    expect(result.status).toBe(200)
    const jsonResponse = await result.json()
    console.log(jsonResponse)
    expect(jsonResponse).toBeDefined()
  }, 1500000)

  // --------------------------------------------------------------------------
  // New Test for Restarting Server Mid-Test with Two AuthFetch Instances
  // --------------------------------------------------------------------------
  test('Test 14: Two AuthFetch instances from the same identity key (restart server mid-test)', async () => {
    // Use separate wallet instances with the same identity key.
    const wallet1 = new MockWallet(privKey)
    const authFetch1 = new AuthFetch(wallet1)
    const resp1 = await authFetch1.fetch('http://localhost:3000/custom-headers', {
      method: 'GET',
      headers: { 'x-bsv-custom-header': 'CustomHeaderValue' }
    })
    expect(resp1.status).toBe(200)
    const data1 = await resp1.json()
    console.log('Data from first AuthFetch instance (before server restart):', data1)
    expect(data1).toBeDefined()

    // Close the server and wait for it to shut down.
    await new Promise<void>((resolve) => {
      server.close(() => {
        console.log('Server closed mid-test')
        resolve()
      })
    })

    // Restart the server and assign it back to the 'server' variable.
    server = startServer(3000)
    await new Promise<void>((resolve, reject) => {
      server.once('listening', () => {
        console.log('Server restarted for second half of the test...')
        resolve()
      })
      server.once('error', (err) => {
        reject(err)
      })
    })

    // Add a short delay to ensure the server is fully ready.
    await new Promise((resolve) => setTimeout(resolve, 200))

    // Create a fresh AuthFetch instance using a new wallet instance (same identity key).
    const resp2 = await authFetch1.fetch('http://localhost:3000/custom-headers', {
      method: 'GET',
      headers: { 'x-bsv-custom-header': 'CustomHeaderValue' }
    })
    expect(resp2.status).toBe(200)
    const data2 = await resp2.json()
    console.log('Data from second AuthFetch instance (after server restart):', data2)
    expect(data2).toBeDefined()
  }, 150000)
})

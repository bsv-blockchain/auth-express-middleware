/**
 * tests/AuthFetch.test.ts
 */
import fs from 'fs'
import path from 'path'
import {
  PrivateKey,
  RequestedCertificateTypeIDAndFieldList,
  Utils,
} from '@bsv/sdk'
import { AuthFetch, createMasterCertificate } from '@bsv/sdk'
import { MockWallet } from './MockWallet'
import { Server } from 'http'
import { startServer } from './testExpressServer.test'

export interface RequestedCertificateSet {
  certifiers: string[]
  types: RequestedCertificateTypeIDAndFieldList
}

describe('AuthFetch and AuthExpress Integration Tests', () => {
  let privKey: PrivateKey
  let server: Server
  privKey = new PrivateKey(1)
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
          'content-type': 'application/json',
        },
        body: JSON.stringify({ message: 'Hello from JSON!' }),
      }
    )
    const result2 = await authFetch.fetch(
      'http://localhost:3000/other-endpoint',
      {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
        },
        body: JSON.stringify({ message: 'Hello from JSON!' }),
      }
    )
    expect(result.status).toBe(200)
    const jsonResponse = await result.json()
    expect(jsonResponse).toBeDefined()
  }, 15000)

  test('Test 2: POST request with URL-encoded data', async () => {
    const walletWithRequests = new MockWallet(privKey)
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
    const walletWithRequests = new MockWallet(privKey)
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
    const walletWithRequests = new MockWallet(privKey)
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
    const walletWithRequests = new MockWallet(privKey)
    const authFetch = new AuthFetch(walletWithRequests)
    const result = await authFetch.fetch('http://localhost:3000/')
    expect(result.status).toBe(200)
    const textResponse = await result.text()
    expect(textResponse).toBeDefined()

  })

  // TODO: Requires modifying the test server to support this.
  // test('Test 6: Fetch and save video', async () => {
  //   const walletWithRequests = new MockWallet(privKey)
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
    const walletWithRequests = new MockWallet(privKey)
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
    const walletWithRequests = new MockWallet(privKey)
    const authFetch = new AuthFetch(walletWithRequests)
    const result = await authFetch.fetch(
      'http://localhost:3000/delete-endpoint',
      {
        method: 'DELETE',
        headers: {
          'x-bsv-test': 'this is a test header',
        },
      }
    )
    expect(result.status).toBe(200)
    const textResponse = await result.text()
    expect(textResponse).toBeDefined()

  })

  test('Test 9: Large binary upload', async () => {
    const walletWithRequests = new MockWallet(privKey)
    const authFetch = new AuthFetch(walletWithRequests)
    const largeBuffer = Utils.toArray('Hello from a large upload test')
    const result = await authFetch.fetch('http://localhost:3000/large-upload', {
      method: 'POST',
      headers: {
        'content-type': 'application/octet-stream',
      },
      body: largeBuffer,
    })
    expect(result.status).toBe(200)
    const textResponse = await result.text()
    expect(textResponse).toBeDefined()

  })

  test('Test 10: Query parameters', async () => {
    const walletWithRequests = new MockWallet(privKey)
    const authFetch = new AuthFetch(walletWithRequests)
    const result = await authFetch.fetch(
      'http://localhost:3000/query-endpoint?param1=value1&param2=value2'
    )
    expect(result.status).toBe(200)
    const textResponse = await result.text()
    expect(textResponse).toBeDefined()

  })

  test('Test 11: Custom headers', async () => {
    const walletWithRequests = new MockWallet(privKey)
    const authFetch = new AuthFetch(walletWithRequests)
    const result = await authFetch.fetch('http://localhost:3000/custom-headers', {
      method: 'GET',
      headers: {
        'x-bsv-custom-header': 'CustomHeaderValue',
      },
    })
    expect(result.status).toBe(200)
    const textResponse = await result.text()
    expect(textResponse).toBeDefined()

  })

  test('Test 12: Certificate request', async () => {
    const requestedCertificates: RequestedCertificateSet = {
      certifiers: [
        '03caa1baafa05ecbf1a5b310a7a0b00bc1633f56267d9f67b1fd6bb23b3ef1abfa',
      ],
      types: {
        'z40BOInXkI8m7f/wBrv4MJ09bZfzZbTj2fJqCtONqCY=': ['firstName'],
      },
    }
    const walletWithRequests = new MockWallet(privKey)
    const certifierPrivateKey = PrivateKey.fromHex(
      '5a4d867377bd44eba1cecd0806c16f24e293f7e218c162b1177571edaeeaecef'
    )
    const certifierWallet = new MockWallet(certifierPrivateKey)
    const certifierPublicKey = certifierPrivateKey.toPublicKey().toString()
    const certificateType = 'z40BOInXkI8m7f/wBrv4MJ09bZfzZbTj2fJqCtONqCY='
    const certificateSerialNumber = Utils.toBase64(new Array(32).fill(2))
    const fields = { firstName: 'Alice', lastName: 'Doe' }
    const masterCert = await createMasterCertificate(
      walletWithRequests,
      fields,
      certificateType,
      certificateSerialNumber,
      certifierPublicKey
    )
    await masterCert.sign(certifierWallet)
    walletWithRequests.addMasterCertificate(masterCert)
    const authWithCerts = new AuthFetch(walletWithRequests)
    const certRequests = [
      authWithCerts.sendCertificateRequest(
        'http://localhost:3000',
        requestedCertificates
      ),
      authWithCerts.sendCertificateRequest(
        'http://localhost:3000',
        requestedCertificates
      ),
    ]
    const certs = await Promise.all(certRequests)
    expect(certs).toBeDefined()
    expect(certs.length).toBe(2)
    // Add further assertions based on expected certificates
  })

  // NOTE: YOU MUST MODIFY THE SERVER SIDE TO REQUEST CERTIFICATES FOR THIS TEST TO PASS:
  // test('Test 13: Simple GET request with certificate requests', async () => {
  //   const requestedCertificates: RequestedCertificateSet = {
  //     certifiers: [
  //       '03caa1baafa05ecbf1a5b310a7a0b00bc1633f56267d9f67b1fd6bb23b3ef1abfa',
  //     ],
  //     types: {
  //       'z40BOInXkI8m7f/wBrv4MJ09bZfzZbTj2fJqCtONqCY=': ['firstName'],
  //     },
  //   }
  //   const walletWithRequests = new MockWallet(privKey)
  //   const certifierPrivateKey = PrivateKey.fromHex(
  //     '5a4d867377bd44eba1cecd0806c16f24e293f7e218c162b1177571edaeeaecef'
  //   )
  //   const certifierWallet = new MockWallet(certifierPrivateKey)
  //   const certifierPublicKey = certifierPrivateKey.toPublicKey().toString()
  //   const certificateType = 'z40BOInXkI8m7f/wBrv4MJ09bZfzZbTj2fJqCtONqCY='
  //   const certificateSerialNumber = Utils.toBase64(new Array(32).fill(2))
  //   const fields = { firstName: 'Alice', lastName: 'Doe' }
  //   const masterCert = await createMasterCertificate(
  //     walletWithRequests,
  //     fields,
  //     certificateType,
  //     certificateSerialNumber,
  //     certifierPublicKey
  //   )
  //   await masterCert.sign(certifierWallet)
  //   walletWithRequests.addMasterCertificate(masterCert)
  //   const authFetchWithRequests = new AuthFetch(
  //     walletWithRequests,
  //     requestedCertificates
  //   )
  //   const result = await authFetchWithRequests.fetch('http://localhost:3000/')
  //   expect(result.status).toBe(200)
  //   const jsonResponse = await result.json()
  //   expect(jsonResponse).toBeDefined()
  //   const certs = authFetchWithRequests.consumeReceivedCertificates()
  //   expect(certs).toBeDefined()
  //   if (certs.length === 0) {
  //     console.log('No certificates received.')
  //   } else {
  //     const cert = certs[0]
  //     for (const fieldName of Object.keys(cert.keyring)) {
  //       const { plaintext: masterFieldKey } = await walletWithRequests.decrypt({
  //         ciphertext: Utils.toArray(cert.keyring[fieldName], 'base64'),
  //         protocolID: [2, 'certificate field encryption'],
  //         keyID: `${cert.serialNumber} ${fieldName}`,
  //         counterparty: 'self',
  //       })
  //       const decryptedFieldBytes = new SymmetricKey(masterFieldKey!).decrypt(
  //         Utils.toArray(cert.fields[fieldName], 'base64')
  //       )
  //       const fieldValue = Utils.toUTF8(decryptedFieldBytes as number[])
  //       expect(fieldValue).toBe(fields[fieldName])
  //     }
  //   }
  // })

  // --------------------------------------------------------------------------
  // Edge-Case Tests
  // --------------------------------------------------------------------------

  test('Edge Case A: No Content-Type', async () => {
    const walletWithRequests = new MockWallet(privKey)
    const authFetch = new AuthFetch(walletWithRequests)
    await expect(
      authFetch.fetch('http://localhost:3000/no-content-type-endpoint', {
        method: 'POST',
        // Intentionally no 'content-type' header
        body: 'This should fail if your code requires Content-Type for POST.',
      })
    ).rejects.toThrow()
  })
})
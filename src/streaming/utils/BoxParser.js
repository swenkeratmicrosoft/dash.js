/**
 * The copyright in this software is being made available under the BSD License,
 * included below. This software may be subject to other third party and contributor
 * rights, including patent rights, and no such rights are granted under this license.
 *
 * Copyright (c) 2013, Dash Industry Forum.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *  * Redistributions of source code must retain the above copyright notice, this
 *  list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright notice,
 *  this list of conditions and the following disclaimer in the documentation and/or
 *  other materials provided with the distribution.
 *  * Neither the name of Dash Industry Forum nor the names of its
 *  contributors may be used to endorse or promote products derived from this software
 *  without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS AS IS AND ANY
 *  EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 *  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 *  IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 *  INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 *  NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 *  PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 *  WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 */

import Debug from '../../core/Debug';
import IsoFile from './IsoFile';
import FactoryMaker from '../../core/FactoryMaker';
import EventBus from '../../core/EventBus';
import Events from '../../core/events/Events';
import ISOBoxer from 'codem-isoboxer';

import IsoBoxSearchInfo from '../vo/IsoBoxSearchInfo';

function BoxParser(/*config*/) {

    let logger,
        instance;
    let context = this.context;
    const eventBus = EventBus(context).getInstance();
    let pendingManifestEmsg = null;
    let verifiedManifests = [];
    let verifiedAuthenticators = [];

    function setup() {
        logger = Debug(context).getInstance().getLogger(instance);
    }

    /**
     * @param {ArrayBuffer} data
     * @returns {IsoFile|null}
     * @memberof BoxParser#
     */
    function parse(data) {
        if (!data) return null;

        if (data.fileStart === undefined) {
            data.fileStart = 0;
        }

        let parsedFile = ISOBoxer.parseBuffer(data);
        let dashIsoFile = IsoFile(context).create();

        dashIsoFile.setData(parsedFile);

        return dashIsoFile;
    }

    /**
     * From the list of type boxes to look for, returns the latest one that is fully completed (header + payload). This
     * method only looks into the list of top boxes and doesn't analyze nested boxes.
     * @param {string[]} types
     * @param {ArrayBuffer|uint8Array} buffer
     * @param {number} offset
     * @returns {IsoBoxSearchInfo}
     * @memberof BoxParser#
     */
    function findLastTopIsoBoxCompleted(types, buffer, offset) {
        if (offset === undefined) {
            offset = 0;
        }

        // 8 = size (uint32) + type (4 characters)
        if (!buffer || offset + 8 >= buffer.byteLength) {
            return new IsoBoxSearchInfo(0, false);
        }

        const data = (buffer instanceof ArrayBuffer) ? new Uint8Array(buffer) : buffer;
        let boxInfo;
        let lastCompletedOffset = 0;
        while (offset < data.byteLength) {
            const boxSize = parseUint32(data, offset);
            const boxType = parseIsoBoxType(data, offset + 4);

            if (boxSize === 0) {
                break;
            }

            if (offset + boxSize <= data.byteLength) {
                if (types.indexOf(boxType) >= 0) {
                    boxInfo = new IsoBoxSearchInfo(offset, true, boxSize);
                } else {
                    lastCompletedOffset = offset + boxSize;
                }
            }

            offset += boxSize;
        }

        if (!boxInfo) {
            return new IsoBoxSearchInfo(lastCompletedOffset, false);
        }

        return boxInfo;
    }

    function getSamplesInfo(ab) {
        if (!ab || ab.byteLength === 0) {
            return {sampleList: [], lastSequenceNumber: NaN, totalDuration: NaN, numSequences: NaN};
        }
        let isoFile = parse(ab);
        // zero or more moofs
        let moofBoxes = isoFile.getBoxes('moof');
        // exactly one mfhd per moof
        let mfhdBoxes = isoFile.getBoxes('mfhd');

        let sampleDuration,
            sampleCompositionTimeOffset,
            sampleCount,
            sampleSize,
            sampleDts,
            sampleList,
            sample,
            i, j, k, l, m, n,
            dataOffset,
            lastSequenceNumber,
            numSequences,
            totalDuration;

        numSequences = isoFile.getBoxes('moof').length;
        lastSequenceNumber = mfhdBoxes[mfhdBoxes.length - 1].sequence_number;
        sampleCount = 0;

        sampleList = [];
        let subsIndex = -1;
        let nextSubsSample = -1;
        for (l = 0; l < moofBoxes.length; l++) {
            let moofBox = moofBoxes[l];
            // zero or more trafs per moof
            let trafBoxes = moofBox.getChildBoxes('traf');
            for (j = 0; j < trafBoxes.length; j++) {
                let trafBox = trafBoxes[j];
                // exactly one tfhd per traf
                let tfhdBox = trafBox.getChildBox('tfhd');
                // zero or one tfdt per traf
                let tfdtBox = trafBox.getChildBox('tfdt');
                sampleDts = tfdtBox.baseMediaDecodeTime;
                // zero or more truns per traf
                let trunBoxes = trafBox.getChildBoxes('trun');
                // zero or more subs per traf
                let subsBoxes = trafBox.getChildBoxes('subs');
                for (k = 0; k < trunBoxes.length; k++) {
                    let trunBox = trunBoxes[k];
                    sampleCount = trunBox.sample_count;
                    dataOffset = (tfhdBox.base_data_offset || 0) + (trunBox.data_offset || 0);

                    for (i = 0; i < sampleCount; i++) {
                        sample = trunBox.samples[i];
                        sampleDuration = (sample.sample_duration !== undefined) ? sample.sample_duration : tfhdBox.default_sample_duration;
                        sampleSize = (sample.sample_size !== undefined) ? sample.sample_size : tfhdBox.default_sample_size;
                        sampleCompositionTimeOffset = (sample.sample_composition_time_offset !== undefined) ? sample.sample_composition_time_offset : 0;
                        let sampleData = {
                            'dts': sampleDts,
                            'cts': (sampleDts + sampleCompositionTimeOffset),
                            'duration': sampleDuration,
                            'offset': moofBox.offset + dataOffset,
                            'size': sampleSize,
                            'subSizes': [sampleSize]
                        };
                        if (subsBoxes) {
                            for (m = 0; m < subsBoxes.length; m++) {
                                let subsBox = subsBoxes[m];
                                if (subsIndex < (subsBox.entry_count - 1) && i > nextSubsSample) {
                                    subsIndex++;
                                    nextSubsSample += subsBox.entries[subsIndex].sample_delta;
                                }
                                if (i == nextSubsSample) {
                                    sampleData.subSizes = [];
                                    let entry = subsBox.entries[subsIndex];
                                    for (n = 0; n < entry.subsample_count; n++) {
                                        sampleData.subSizes.push(entry.subsamples[n].subsample_size);
                                    }
                                }
                            }
                        }
                        sampleList.push(sampleData);
                        dataOffset += sampleSize;
                        sampleDts += sampleDuration;
                    }
                }
                totalDuration = sampleDts - tfdtBox.baseMediaDecodeTime;
            }
        }
        return {sampleList: sampleList, lastSequenceNumber: lastSequenceNumber, totalDuration: totalDuration, numSequences: numSequences};
    }

    function getMediaTimescaleFromMoov(ab) {
        let isoFile = parse(ab);
        let mdhdBox = isoFile ? isoFile.getBox('mdhd') : undefined;

        return mdhdBox ? mdhdBox.timescale : NaN;
    }

    function parseUint32(data, offset) {
        return data[offset + 3] >>> 0 |
            (data[offset + 2] << 8) >>> 0 |
            (data[offset + 1] << 16) >>> 0 |
            (data[offset] << 24) >>> 0;
    }

    function parseIsoBoxType(data, offset) {
        return String.fromCharCode(data[offset++]) +
            String.fromCharCode(data[offset++]) +
            String.fromCharCode(data[offset++]) +
            String.fromCharCode(data[offset]);
    }

    function findInitRange(data) {
        let initRange = null;
        let start,
            end;

        const isoFile = parse(data);

        if (!isoFile) {
            return initRange;
        }

        const ftyp = isoFile.getBox('ftyp');
        const moov = isoFile.getBox('moov');

        logger.debug('Searching for initialization.');

        if (moov && moov.isComplete) {
            start = ftyp ? ftyp.offset : moov.offset;
            end = moov.offset + moov.size - 1;
            initRange = start + '-' + end;

            logger.debug('Found the initialization.  Range: ' + initRange);
        }

        return initRange;
    }

    function compare(arr1, arr2) {
        if (arr1.length !== arr2.length) {
            return false;
        }
        for (let ib = 0; ib < arr1.length; ib++) {
            if (arr1[ib] !== arr2[ib]) {
                return false;
            }
        }
        return true;
    }

    function ShaPromise(dataToHash, expectedHash) {
        return new Promise(function (resolve, reject) {
            window.crypto.subtle.digest('SHA-256', dataToHash).then(function (computedCoreDigestBuf) {
                return resolve({ hash: new Uint8Array(computedCoreDigestBuf), expectedHash: expectedHash });
            }).catch (function (e) {
                return reject(e);
            });
        });
    }

    // Unbelievable: No native PEM support in asn1js/pkijs.
    function PEMToCert(pem) {
        const asn1js = require('asn1js');
        const pkijs = require('pkijs');
        const Certificate = pkijs.Certificate;

        const b64 = pem.replace(/(-----(BEGIN|END) CERTIFICATE-----|[\n\r])/g, '');
        const bytes = window.atob(b64);

        let length = bytes.length;
        let out = new Uint8Array(length);
        while (length--) {
            out[length] = bytes.charCodeAt(length);
        }

        const ber = new Uint8Array(out).buffer;

        const asn1 = asn1js.fromBER(ber);
        const certificate = new Certificate({ schema: asn1.result });
        return certificate;
    }

    function ampOnInitFragmentLoaded(data) {
        ampVerifyManifest(data).then(function (manifest) {
            if (manifest !== null) {
                eventBus.trigger(Events.AMP_MANIFEST_FOUND,
                    { sender: this, manifest: manifest, error: null });
            }
        }).catch(function (e) {
            eventBus.trigger(Events.AMP_MANIFEST_FOUND,
                { sender: this, error: e });
        });
    }

    function ampOnMediaFragmentLoaded(data) {
        ampVerifyHash(data).then(function (chunkStr) {
            if (chunkStr !== null) {
                eventBus.trigger(Events.AMP_STATE_CHANGED,
                    { sender: this, isVerified: true, chunkStr: chunkStr, error: null});
            }
        }).catch(function (e) {
            eventBus.trigger(Events.AMP_STATE_CHANGED,
                { sender: this, error: e });
        });
    }

    function ampVerifyManifest(data) {

        return new Promise(function (resolve, reject) {
            const isoFile = parse(data);

            if (!isoFile) {
                return resolve(null);
            }

            const emsgs = isoFile.getBoxes('emsg');

            if (!emsgs) {
                return resolve(null);
            }

            let emsg = null;
            for (let i = 0, ln = emsgs.length; i < ln; i++) {
                if (emsgs[i].scheme_id_uri === 'urn:mpeg:amp:manifest:emsg') {
                    emsg = emsgs[i];
                }
            }

            if (!emsg) {
                return resolve(null);
            }

            ampVerifyManifestMsg(0, isoFile, emsg).then(function (manifest) {
                pendingManifestEmsg = null;
                return resolve(manifest);
            }).catch(function (e) {
                pendingManifestEmsg = null;
                return reject(new Error('ampVerifyManifest error: ' + e));
            });
        });
    }

    function ampVerifyManifestMsg(attempts, isoFile, emsg) {

        let pending = true;
        if (pendingManifestEmsg === null) {
            pendingManifestEmsg = emsg;
            pending = false;
        }

        return new Promise(function (resolve, reject) {

            let message_data = emsg.message_data.buffer.slice(emsg.message_data.byteOffset, emsg.message_data.byteOffset + emsg.message_data.byteLength);
            let msgdata = new Uint8Array(message_data);

            let CBOR = require('cbor-js');
            let manifest = CBOR.decode(message_data);

            if (pending) {
                if (attempts < 100) {
                    setTimeout(function () {
                        return ampVerifyManifestMsg(attempts + 1, isoFile, emsg).then(function (manifest) {
                            return resolve(manifest);
                        }).catch(function (e) {
                            return reject(e);
                        });
                    }, 10);
                } else {
                    return reject(new Error('Pending manifest never completed verification'));
                }
            }

            let trexBox = isoFile.getBox('trex');
            let mdhdBox = isoFile.getBox('mdhd');
            let mvhdBox = isoFile.getBox('mvhd');

            let verified = false;
            let jsonStr = JSON.stringify(msgdata);
            for (let iVerified = 0; iVerified < verifiedManifests.length && !verified; iVerified++) {
                let jsonStrNext = JSON.stringify(verifiedManifests[iVerified]);
                if (jsonStr.localeCompare(jsonStrNext) === 0) {
                    verified = true;
                }
            }

            if (verified) {
                for (let i = 0; i < verifiedAuthenticators.length; i++) {
                    if (verifiedAuthenticators[i].moovId === emsg.id) {
                        verifiedAuthenticators[i].trexBox = trexBox;
                        verifiedAuthenticators[i].mdhdBox = mdhdBox;
                        verifiedAuthenticators[i].mvhdBox = mvhdBox;
                    }
                }
                pendingManifestEmsg = null;
                return resolve(null);
            }

            // Verifying a Manifest Algorithm Step 1. Fail unless the following versions are all === 1
            if (manifest.version !== 1 ||
                manifest.coreManifest.version !== 1 ||
                manifest.facsimileInfo.version !== 1 ||
                manifest.publisherEvidence.version !== 1) {
                return reject(new Error('Invalid version'));
            }

            // Verifying a Manifest Algorithm Step 2. Fail unless DigestAlgorithm is set to 'SHA-256'
            if (manifest.coreManifest.digestAlgorithm !== 'SHA-256') {
                return reject(new Error('Invalid digestAlgorithm: ' + manifest.coreManifest.digestAlgorithm));
            }

            let shaFacsimilePromises = [];
            let authenticators = [];
            for (let iRecord = 0; iRecord < manifest.facsimileInfo.records.length; iRecord++) {

                // Verifying a Manifest Algorithm Step 3. Fail unless a Records[*] has a ChunkData with ChunkingScheme === 2 (Iso Box Authenticator)
                let authenticator = null;
                for (let iChunkData = 0; iChunkData < manifest.facsimileInfo.records[iRecord].facsimile.chunkData.length && authenticator === null; iChunkData++) {
                    if (manifest.facsimileInfo.records[iRecord].facsimile.chunkData[iChunkData].chunkingScheme === 2) {
                        authenticator = manifest.facsimileInfo.records[iRecord].facsimile.chunkData[iChunkData];
                    }
                }
                if (authenticator === null) {
                    return reject(new Error('No ISO Box Authenticator found for record ' + iRecord));
                }
                if (authenticator.numChunks === 0) {
                    return reject(new Error('Invalid authenticator (zero chunk count) in record ' + iRecord));
                }
                authenticators.push(authenticator);

                // Note: No step 4.  (Previous versions had a step 4.)

                // Verifying a Manifest Algorithm Step 5. Fail unless Records[*].IndexIntoFacsimileDescriptorDigests < FacsimileDescriptorDigests.cItems
                if (manifest.facsimileInfo.records[iRecord].index >= manifest.coreManifest.facsimileDescriptorCborDigests.length) {
                    return reject(new Error('Index out of bounds in record ' + iRecord));
                }

                // Verifying a Manifest Algorithm Step 6. Fail unless SHA256( cbor-of( Records[*].FacsimileDescriptor ) )
                //                                                === FacsimileDescriptorDigests[ Records[*].IndexIntoFacsimileDescriptorDigests ]

                // Because WebCrypto methods are async, defer verification until we can do all at once
                let manifestFacsimileDigest = manifest.coreManifest.facsimileDescriptorCborDigests[manifest.facsimileInfo.records[iRecord].index];
                let cborFacsimile = new Uint8Array(CBOR.encode(manifest.facsimileInfo.records[iRecord].facsimile));

                shaFacsimilePromises.push(ShaPromise(cborFacsimile, manifestFacsimileDigest));
            }

            Promise.all(shaFacsimilePromises).then(function (shaPromiseResults) {

                for (let iSha = 0; iSha < shaPromiseResults.length; iSha++) {
                    let shaPromiseResult = shaPromiseResults[iSha];
                    let hash = shaPromiseResult.hash;
                    let expectedHash = shaPromiseResult.expectedHash;
                    if (!compare(hash, expectedHash)) {
                        return reject(new Error('Incorrect SHA256( cbor-of( Records[*].FacsimileDescriptor ) ) for record ' + iSha));
                    }
                }

                // Verifying a Manifest Algorithm Step 7. Fail unless CoseSignatureToken is well-formed
                let coseData = manifest.publisherEvidence.coseSignatureToken;
                if (coseData.length !== 107 ||
                    coseData[0] !== 0xD2 ||
                    coseData[2] !== 0x43 ||
                    coseData[3] !== 0xA1 ||
                    coseData[4] !== 0x01 ||
                    coseData[5] !== 0x26 ||
                    coseData[6] !== 0xA0 ||
                    coseData[7] !== 0x58 ||
                    coseData[8] !== 0x20 ||
                    coseData[41] !== 0x58 ||
                    coseData[42] !== 0x40) {
                    return reject(new Error('Cose signature token is malformed: ' + coseData));
                }

                // Verifying a Manifest Algorithm Step 8. Fail unless SHA256( cbor-of( CoreManifest ) )
                //                                                === the value from CoseSignatureToken at the appropriate offset
                let manifestCoreDigest = coseData.slice(9, 41);
                let cborCoreData = CBOR.encode(manifest.coreManifest);

                let crypto = window.crypto.subtle;

                crypto.digest('SHA-256', cborCoreData).then(function (computedCoreDigestBuf) {

                    let computedCoreDigest = new Uint8Array(computedCoreDigestBuf);

                    if (!compare(manifestCoreDigest, computedCoreDigest)) {
                        return reject(new Error('Manifest hash !== computed SHA256( cbor-of( CoreManifest ) ) where first byte of each: ' + manifestCoreDigest[0] + ' vs ' + computedCoreDigest[0]));
                    }

                    // Verifying a Manifest Algorithm Step 9. Fail unless the following succeeds
                    //  ECDSA-P256-SHA256-Verify( [To Sign, see comments in drmprovenancemanifest.h], pubkey-from( PemEncodedCertificates[0] ) )
                    let coseEccSignature = coseData.slice(43);

                    let coseEccToVerifyHeader = new Uint8Array([0x84, 0x6A, 0x53, 0x69, 0x67, 0x6E, 0x61, 0x74, 0x75, 0x72, 0x65, 0x31, 0x43, 0xA1, 0x01, 0x26, 0x40, 0x58, 0x20]);
                    let coseEccToVerify = new Uint8Array(coseEccToVerifyHeader.length + manifestCoreDigest.length);
                    coseEccToVerify.set(coseEccToVerifyHeader);
                    coseEccToVerify.set(manifestCoreDigest, coseEccToVerifyHeader.length);

                    let leafCertPEM = manifest.publisherEvidence.pemEncodedCertificates[0];
                    let leafCert = PEMToCert(leafCertPEM);

                    leafCert.getPublicKey().then(function (leafCertPubkey) {
                        let algorithm = {
                            name: 'ECDSA',
                            hash: { name: 'SHA-256' }
                        };
                        window.crypto.subtle.verify(
                            algorithm,
                            leafCertPubkey,
                            coseEccSignature,
                            coseEccToVerify).then(function (signatureVerified) {
                                if (!signatureVerified) {
                                    return reject(new Error('Signature on manifest did not verify against public key in leaf certificate'));
                                }

                                let certVerifyPromises = [];
                                let child = leafCert;
                                for (let iCert = 1; iCert < manifest.publisherEvidence.pemEncodedCertificates.length; iCert++) {
                                    let parentPEM = manifest.publisherEvidence.pemEncodedCertificates[iCert];
                                    let parent = PEMToCert(parentPEM);
                                    certVerifyPromises.push(child.verify(parent));
                                    child = parent;
                                }

                                // PEM-encoded but without the BEGIN/END certificate tags and newlines
                                const trustedRootCertPEM = 'MIICIjCCAYSgAwIBAgIUf9/9keFEavW4LnXSrQD2Jo75gGkwCgYIKoZIzj0EAwIwIzEhMB8GA1UEAwwYTWVkaWEgUHJvdmVuYW5jZSBSb290IENBMB4XDTIwMDQyOTIwMTUwOFoXDTMwMDQyNzIwMTUwOFowIzEhMB8GA1UEAwwYTWVkaWEgUHJvdmVuYW5jZSBSb290IENBMIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQA8pv3tfFcfUItqL1OeG0j1l77S/6Lo5mkjKyeskfh5saPF3/JeIyin7/KxpN2nFAYVMhhRRzLUHVw/SYx5zsMQBABJlRklEE4xftdiYSbIqSImZNjFsxXcBlV3Ac6cIpTf/tU6eVDooBqWbFTP8k8wJ7kEqjx0ImXSeByFiNc1yDT7lOjUzBRMB0GA1UdDgQWBBQMAkHuuRDP4yV6UK6LadUD/lXaEzAfBgNVHSMEGDAWgBQMAkHuuRDP4yV6UK6LadUD/lXaEzAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA4GLADCBhwJCAJGVBXVZ28AIgCS2RCvxb2/0InbJUnNq6pV1Y9/3s8f1lBwQ9g1yRk8EMWMhyZtWTrhWnoMHGFRBkOx6a2GUPR6aAkFYPbC4kR14hhTkViaYehQr5Ec6IyiZIO/i5dPWd65FmkHJRj4kHDja03ggUK6DQ+jpf6va5IbeI0CH3d831UiviQ==';
                                let trustedRootCert = PEMToCert(trustedRootCertPEM);
                                certVerifyPromises.push(child.verify(trustedRootCert));

                                Promise.all(certVerifyPromises).then(function (certVerifyPromiseResults) {

                                    for (let iVerif = 0; iVerif < certVerifyPromiseResults.length; iVerif++) {
                                        if (!certVerifyPromiseResults[iVerif]) {
                                            return reject(new Error('Certificate in chain failed to verify: ' + iVerif));
                                        }
                                    }

                                    for (let iVerified = 0; iVerified < verifiedManifests.length && !verified; iVerified++) {
                                        let jsonStrNext = JSON.stringify(verifiedManifests[iVerified]);
                                        if (jsonStr.localeCompare(jsonStrNext) === 0) {
                                            verified = true;
                                        }
                                    }

                                    if (verified) {
                                        for (let i = 0; i < verifiedAuthenticators.length; i++) {
                                            if (verifiedAuthenticators[i].moovId === emsg.id) {
                                                verifiedAuthenticators[i].trexBox = trexBox;
                                                verifiedAuthenticators[i].mdhdBox = mdhdBox;
                                                verifiedAuthenticators[i].mvhdBox = mvhdBox;
                                            }
                                        }
                                    } else {
                                        verifiedManifests.push(msgdata);

                                        for (let i = 0; i < authenticators.length; i++) {
                                            if (authenticators[i].moovId === emsg.id) {
                                                authenticators[i].trexBox = trexBox;
                                                authenticators[i].mdhdBox = mdhdBox;
                                                authenticators[i].mvhdBox = mvhdBox;
                                            } else {
                                                authenticators[i].trexBox = null;
                                                authenticators[i].mdhdBox = null;
                                                authenticators[i].mvhdBox = null;
                                            }
                                            verifiedAuthenticators.push(authenticators[i]);
                                        }
                                    }

                                    pendingManifestEmsg = null;
                                    if (verified) {
                                        return resolve(null);
                                    } else {
                                        return resolve(manifest);
                                    }

                                }).catch(function (e) {
                                    return reject(new Error('Unable to verify certificate chain with error: ' + e));
                                });
                            }).catch(function (e) {
                                return reject(new Error('Unable to verify signature on manifest with error: ' + e));
                            });
                    }).catch(function (e) {
                        return reject(e);
                    });
                }).catch(function (e) {
                    return reject(e);
                });
            }).catch(function (e) {
                return reject(e);
            });
        });
    }

    function appendDwordAsBE(arr, dwordToPush) {
        let result = new Uint8Array(arr.length + 4);
        result.set(arr);

        result[arr.length + 0] = (dwordToPush & 0xFF000000) >> 24;
        result[arr.length + 1] = (dwordToPush & 0x00FF0000) >> 16;
        result[arr.length + 2] = (dwordToPush & 0x0000FF00) >> 8;
        result[arr.length + 3] = (dwordToPush & 0x000000FF) >> 0;
        return result;
    }

    function appendArray(arr, arrToPush) {
        let result = new Uint8Array(arr.length + arrToPush.length);
        result.set(arr);
        result.set(arrToPush, arr.length);
        return result;
    }

    function computeDepth(nodes) {
        let depth = 0;
        while ((1 << depth) < nodes) {
            depth++;
        }
        return depth + 1;
    }

    function computeRowStartIdxFromDepthOfRow(rowDepth) {
        return (1 << (rowDepth - 1)) - 1;
    }

    function computePeerIdx(idx) {
        if ((idx & 1) !== 0) {
            return idx + 1;
        }
        else {
            return idx - 1;
        }
    }

    function computeHashCount(treeDepth) {
        return (1 << treeDepth) - 1;
    }

    function computeLeftChildIdx(idxNode) {
        return (idxNode << 1) + 1;
    }

    function doesNodeExist(cChunks, treeDepth, idxNode) {
        let cMaxHashes = computeHashCount(treeDepth);
        let idxMin = computeRowStartIdxFromDepthOfRow(treeDepth);
        while (idxNode < idxMin) {
            idxNode = computeLeftChildIdx(idxNode);
        }
        return (idxNode < cMaxHashes) && ((idxNode - idxMin) < cChunks);
    }

    function computeParentIdx(idxNode) {
        return (idxNode - 1) >> 1;
    }

    function foldHash(left, right, fibHash) {
        if (right !== null) {
            let toHash = new Uint8Array(64);
            toHash.set(left);
            toHash.set(right, left.length);
            return ShaPromise(toHash, fibHash);
        } else {
            return new Promise(function (resolve, reject) {
                if (left !== null) {
                    return resolve({ hash: left, expectedHash: fibHash});
                } else {
                    return reject(new Error('Unable to derive Merkle Tree hash due to null left hash'));
                }
            });
        }
    }

    function foldHashes(folds, fibHash) {
        if (folds.length === 1) {
            return foldHash(folds[0].left, folds[0].right, fibHash);
        } else {
            return foldHash(folds[0].left, folds[0].right, fibHash).then(function (nextHash) {
                folds = folds.slice(1);

                if (folds[0].left === null) {
                    folds[0].left = nextHash.hash;
                } else {
                    if (folds[0].right !== null) {
                        return Promise.reject(new Error('Unable to derive Merkle Tree hash due to unexpected non-null hash in foldHashes'));
                    }
                    folds[0].right = nextHash.hash;
                }

                return foldHashes(folds, fibHash);
            });
        }
    }

    function GetChunkStr(moov_id, track_id, sequence_number, hash_location) {
        return 'moov_id=' + moov_id +
            ', track_id=' + track_id +
            ', sequence_number=' + sequence_number +
            ', hash_location=' + hash_location;
    }

    function evaluateMerkleTree(cChunks, idxChunk, chunkHash, cibHashes, fibHashArray) {
        if (cChunks === 1) {
            return new Promise(function (resolve, reject) {
                if (chunkHash !== null) {
                    return resolve({ hash: chunkHash, expectedHash: fibHashArray[0] });
                } else {
                    return reject(new Error('Unable to derive Merkle Tree hash due to chunkHash is null'));
                }
            });
        }
        let cFibHashes = fibHashArray.length;
        let treeDepth = computeDepth(cChunks);
        let fibDepth = computeDepth(cFibHashes);
        let idxStart = computeRowStartIdxFromDepthOfRow(treeDepth) + idxChunk;
        let idxMin = computeRowStartIdxFromDepthOfRow(fibDepth + 1);

        let folds = [];
        let ibCIBHashes = 0;

        let idxNextPeer = 0;
        for (idxNextPeer = computePeerIdx(idxStart);
            idxNextPeer >= idxMin;
            idxNextPeer = computePeerIdx(idxNextPeer)) {

            if (doesNodeExist(cChunks, treeDepth, idxNextPeer)) {
                let left = null;
                let right = null;
                if ((idxNextPeer & 1) === 1) {
                    left = cibHashes.slice(ibCIBHashes, ibCIBHashes + 32);
                    if (folds.length === 0) {
                        right = chunkHash;
                    }
                }
                else {
                    if (folds.length === 0) {
                        left = chunkHash;
                    }
                    right = cibHashes.slice(ibCIBHashes, ibCIBHashes + 32);
                }
                ibCIBHashes += 32;
                folds.push({ left: left, right: right });
            }

            idxNextPeer = computeParentIdx(idxNextPeer);
            if (idxNextPeer === 0) {
                break;
            }
        }

        let idxFibHashes = 0;
        if (idxNextPeer > 0) {
            idxFibHashes = computePeerIdx(idxNextPeer);
            idxMin = computeRowStartIdxFromDepthOfRow(fibDepth);
            if (idxFibHashes < idxMin) {
                return Promise.reject(new Error('Unable to derive Merkle Tree hash due to out-of-bounds'));
            }
            idxFibHashes -= idxMin;
        }

        if (idxFibHashes >= cFibHashes) {
            return Promise.reject(new Error('Authenticator hash list is too short'));
        }

        return foldHashes(folds, fibHashArray[idxFibHashes]);
    }

    function ampVerifyHash(data) {

        return new Promise(function (resolve, reject) {

            const isoFile = parse(data);

            if (!isoFile) {
                return resolve(null);
            }

            const emsgs = isoFile.getBoxes('emsg');

            if (!emsgs) {
                return resolve(null);
            }

            let emsg = null;
            for (let i = 0, ln = emsgs.length; i < ln; i++) {
                if (emsgs[i].scheme_id_uri === 'urn:mpeg:amp:chunk:emsg') {
                    emsg = emsgs[i];
                }
            }

            if (!emsg) {
                return resolve(null);
            }

            ampVerifyHashMsg(0, isoFile, emsg).then(function (chunkStr) {
                return resolve(chunkStr);
            }).catch(function (e) {
                return reject(new Error('ampVerifyHash error: Unable to verify chunk with error: ' + e));
            });
        });
    }

    function ampVerifyHashMsg(attempts, isoFile, emsg) {

        let message_data = emsg.message_data.buffer.slice(emsg.message_data.byteOffset, emsg.message_data.byteOffset + emsg.message_data.byteLength);
        let dataView = new DataView(message_data);
        let moov_id = dataView.getUint32(0);
        let track_id = dataView.getUint32(4);
        let sequence_number = dataView.getUint32(8);
        let hash_location = dataView.getUint16(12);
        let hash_size = dataView.getUint8(14);
        let hash_count = dataView.getUint8(15);
        let cibHashes = new Uint8Array(message_data.slice(16));

        let chunkStr = GetChunkStr(moov_id, track_id, sequence_number, hash_location);

        let authenticator = null;
        for (let iAuth = 0; iAuth < verifiedAuthenticators.length; iAuth++) {
            if (verifiedAuthenticators[iAuth].moovId === moov_id &&
                verifiedAuthenticators[iAuth].streamId === track_id &&
                verifiedAuthenticators[iAuth].trexBox !== null &&
                verifiedAuthenticators[iAuth].mdhdBox !== null &&
                verifiedAuthenticators[iAuth].mvhdBox !== null) {
                authenticator = verifiedAuthenticators[iAuth];
            }
        }

        if (authenticator === null) {
            return new Promise(function (resolve, reject) {
                if (attempts < 100) {
                    // Assume manifest is still verifying and try again for up to 1 second total (100 * 10 ms)
                    setTimeout(function () { ampVerifyHashMsg(attempts + 1, isoFile, emsg); return resolve(chunkStr); }, 10);
                } else {
                    return reject(new Error('No authenticator found for this chunk'));
                }
            });
        }

        return new Promise(function (resolve, reject) {
            let hashes = new Uint8Array(message_data.slice(16));
            if (hash_size !== 32) {
                return reject(new Error('Hash size is not 32'));
            }
            if (hashes.length !== hash_count * hash_size) {
                return reject(new Error('Chunk data has the wrong size ' + hashes.length + ' vs ' + (hash_count * hash_size)));
            }

            let toHash = new Uint8Array();

            let mdhdTimescale = 0;
            if (authenticator.mdhdBox) {
                mdhdTimescale = authenticator.mdhdBox.timescale;
            }
            toHash = appendDwordAsBE(toHash, mdhdTimescale, 'mdhdTimescale');

            if (mdhdTimescale === 0) {
                let mvhdTimescale = authenticator.mvhdBox.timescale;
                toHash = appendDwordAsBE(toHash, mvhdTimescale, 'mvhdTimescale');
            }

            const trunBoxes = isoFile.getBoxes('trun');

            toHash = appendDwordAsBE(toHash, trunBoxes.length, 'trunBoxes.length');

            for (let iTrun = 0; iTrun < trunBoxes.length; iTrun++) {
                const trunBox = trunBoxes[iTrun];
                toHash = appendDwordAsBE(toHash, trunBox.version, 'trunBox.version');
                toHash = appendDwordAsBE(toHash, trunBox.sample_count, 'trunBox.sample_count');
                toHash = appendDwordAsBE(toHash, trunBox.flags, 'trunBox.flags');
            }

            const tfhdBox = isoFile.getBox('tfhd');
            toHash = appendDwordAsBE(toHash, tfhdBox.flags, 'tfhdBox.flags');

            if (authenticator.trexBox) {
                toHash = appendDwordAsBE(toHash, authenticator.trexBox.default_sample_duration, 'authenticator.trexBox.default_sample_duration');
            }

            if ((tfhdBox.flags & 0x008) !== 0) {
                toHash = appendDwordAsBE(toHash, tfhdBox.default_sample_duration, 'tfhdBox.default_sample_duration');
            }

            const mdatBox = isoFile.getBox('mdat');

            let mdatOffset = 0;
            for (let iTrun = 0; iTrun < trunBoxes.length; iTrun++) {
                const trunBox = trunBoxes[iTrun];

                for (let iSample = 0; iSample < trunBox.samples.length; iSample++) {
                    const sample = trunBox.samples[iSample];
                    if ((trunBox.flags & 0x800) !== 0) {
                        toHash = appendDwordAsBE(toHash, sample.sample_composition_time_offset, 'sample.sample_composition_time_offset');
                    }
                    if ((trunBox.flags & 0x100) !== 0) {
                        toHash = appendDwordAsBE(toHash, sample.sample_duration, 'sample.sample_duration');
                    }

                    let sampleSize = 0;
                    if ((trunBox.flags & 0x200) !== 0) {
                        sampleSize = sample.sample_size;
                    } else if ((tfhdBox.flags & 0x002) !== 0) {
                        sampleSize = tfhdBox.default_sample_size;
                    } else if (!authenticator.trexBox) {
                        return reject(new Error('Boxes trun and tfhd did not have sample size and box trex box does not exist'));
                    } else {
                        sampleSize = authenticator.trexBox.default_sample_size;
                    }

                    let sliceStart = mdatBox.data.byteOffset + mdatOffset;
                    let sliceEnd = sliceStart + sampleSize;

                    let mdat_data = mdatBox.data.buffer.slice(sliceStart, sliceEnd);
                    let mdatData = new Uint8Array(mdat_data);

                    toHash = appendArray(toHash, mdatData);
                    mdatOffset += sampleSize;
                }
            }

            ShaPromise(toHash, null).then(function (shaPromiseResults) {
                evaluateMerkleTree(authenticator.numChunks, hash_location, shaPromiseResults.hash, cibHashes, authenticator.merkleTreeDigests).then(function (finalComputedHashResult) {
                    if (!compare(finalComputedHashResult.hash, finalComputedHashResult.expectedHash)) {
                        return reject(new Error('Incorrect SHA256( chunk )'));
                    } else {
                        return resolve(chunkStr);
                    }
                }).catch(function (e) {
                    return reject(e);
                });
            }).catch(function (e) {
                return reject(e);
            });
        });
    }

    instance = {
        parse: parse,
        findLastTopIsoBoxCompleted: findLastTopIsoBoxCompleted,
        getMediaTimescaleFromMoov: getMediaTimescaleFromMoov,
        getSamplesInfo: getSamplesInfo,
        findInitRange: findInitRange,
        ampOnInitFragmentLoaded: ampOnInitFragmentLoaded,
        ampOnMediaFragmentLoaded: ampOnMediaFragmentLoaded
    };

    setup();

    return instance;
}
BoxParser.__dashjs_factory_name = 'BoxParser';
export default FactoryMaker.getSingletonFactory(BoxParser);

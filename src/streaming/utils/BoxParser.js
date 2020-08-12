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
import ISOBoxer from 'codem-isoboxer';

import IsoBoxSearchInfo from '../vo/IsoBoxSearchInfo';

function BoxParser(/*config*/) {

    let logger,
        instance;
    let context = this.context;
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

    function ampVerifyManifest(data) {
        const isoFile = parse(data);

        if (!isoFile) {
            return;
        }

        const emsgs = isoFile.getBoxes('emsg');

        if (!emsgs) {
            logger.fatal('ampVerifyManifest error: no emsgs');
            return;
        }

        let emsg = null;
        for (let i = 0, ln = emsgs.length; i < ln; i++) {
            if (emsgs[i].scheme_id_uri === 'urn:mpeg:amp:manifest:emsg') {
                emsg = emsgs[i];
            }
        }

        if (!emsg) {
            logger.fatal('ampVerifyManifest error: no emsg with AMP manifest urn');
            return;
        }

        let message_data = emsg.message_data.buffer.slice(emsg.message_data.byteOffset, emsg.message_data.byteOffset + emsg.message_data.byteLength);
        let msgdata = new Uint8Array(message_data);

        let verified = false;
        let jsonStr = JSON.stringify(msgdata);
        for (let iVerified = 0; iVerified < verifiedManifests.length && !verified; iVerified++) {
            let jsonStrNext = JSON.stringify(verifiedManifests[iVerified]);
            if (jsonStr.localeCompare(jsonStrNext) === 0) {
                verified = true;
            }
        }

        if (verified) {
            logger.fatal('ampVerifyManifest: This manifest was already verified.');
            return;
        }

        var CBOR = require('cbor-js');
        var manifest = CBOR.decode(message_data);

        // Verifying a Manifest Algorithm Step 1. Fail unless the following versions are all === 1
        if (manifest.version !== 1 ||
            manifest.coreManifest.version !== 1 ||
            manifest.facsimileInfo.version !== 1 ||
            manifest.publisherEvidence.version !== 1) {
            logger.fatal('ampVerifyManifest error: invalid version');
            return;
        }

        // Verifying a Manifest Algorithm Step 2. Fail unless DigestAlgorithm is set to "SHA-256"
        if (manifest.coreManifest.digestAlgorithm !== 'SHA-256') {
            logger.fatal('ampVerifyManifest error: invalid digestAlgorithm: ' + manifest.coreManifest.digestAlgorithm);
            return;
        }

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
                logger.fatal('ampVerifyManifest error: no ISO Box Authenticator found for record ' + iRecord);
                return;
            }
            authenticators.push(authenticator);

            // Note: No step 4.  (Previous versions had a step 4.)

            // Verifying a Manifest Algorithm Step 5. Fail unless Records[*].IndexIntoFacsimileDescriptorDigests < FacsimileDescriptorDigests.cItems
            if (manifest.facsimileInfo.records[iRecord].index >= manifest.coreManifest.facsimileDescriptorCborDigests.length) {
                logger.fatal('ampVerifyManifest error: index out of bounds in record ' + iRecord);
                return;
            }

            // Verifying a Manifest Algorithm Step 6. Fail unless SHA256( cbor-of( Records[*].FacsimileDescriptor ) )
            //                                                === FacsimileDescriptorDigests[ Records[*].IndexIntoFacsimileDescriptorDigests ]
            let manifestFacsimileDigest = manifest.coreManifest.facsimileDescriptorCborDigests[manifest.facsimileInfo.records[iRecord].index];
            let cborFacsimile = new Uint8Array(CBOR.encode(manifest.facsimileInfo.records[iRecord].facsimile));

            // TODO: computedFacsimileDigest should be SHA256(cborFacsimile)
            let computedFacsimileDigest = cborFacsimile;

            if (manifestFacsimileDigest.length !== computedFacsimileDigest.length) {
                logger.fatal('ampVerifyManifest error: manifestFacsimileDigest.length !== computedFacsimileDigest.length ' + manifestFacsimileDigest.length + ' vs ' + computedFacsimileDigest.length);
                //TODO: return;
            }
            if (manifestFacsimileDigest !== computedFacsimileDigest) {
                logger.fatal('ampVerifyManifest error: incorrect SHA256( cbor-of( Records[*].FacsimileDescriptor ) ) for record ' + iRecord);
                //TODO: return;
            }
        }

        // Verifying a Manifest Algorithm Step 7. Fail unless CoseSignatureToken is well-formed
        var coseData = manifest.publisherEvidence.coseSignatureToken;
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
            logger.fatal('ampVerifyManifest error: cose signature token is malformed: ' + coseData);
            return;
        }

        // Verifying a Manifest Algorithm Step 8. Fail unless SHA256( cbor-of( CoreManifest ) )
        //                                                === the value from CoseSignatureToken at the appropriate offset
        let manifestCoreDigest = coseData.slice(9, 41);
        let cborCore = new Uint8Array(CBOR.encode(manifest.coreManifest));

        // TODO: computedCoreDigest should be SHA256(cborCore)
        let computedCoreDigest = cborCore;

        if (manifestCoreDigest.length !== computedCoreDigest.length) {
            logger.fatal('ampVerifyManifest error: manifestCoreDigest.length !== computedCoreDigest.length ' + manifestCoreDigest.length + ' vs ' + computedCoreDigest.length);
            //TODO: return;
        }
        if (manifestCoreDigest !== computedCoreDigest) {
            logger.fatal('ampVerifyManifest error: incorrect SHA256( cbor-of( CoreManifest ) )');
            //TODO: return;
        }

        // Verifying a Manifest Algorithm Step 9. Fail unless the following succeeds
        //  ECDSA-P256-SHA256-Verify( [To Sign, see comments in drmprovenancemanifest.h], pubkey-from( PemEncodedCertificates[0] ) )
        let manifestCoseEccSignature = coseData.slice(43);
        logger.fatal('TODO: this log only exists for compilation success: manifestCoseEccSignature  ' + manifestCoseEccSignature);

        let coseEccToSignHeader = new Uint8Array([0x84, 0x6A, 0x53, 0x69, 0x67, 0x6E, 0x61, 0x74, 0x75, 0x72, 0x65, 0x31, 0x43, 0xA1, 0x01, 0x26, 0x40, 0x58, 0x20]);
        let coseEccToSign = new Uint8Array(coseEccToSignHeader.length + manifestCoreDigest.length);
        coseEccToSign.set(coseEccToSignHeader);
        coseEccToSign.set(manifestCoreDigest, coseEccToSignHeader.length);

        let leafCert = manifest.publisherEvidence.pemEncodedCertificates[0];

        //TODO: Parse the public key from leafCert
        let leafPubkey = leafCert;
        logger.fatal('TODO: this log only exists for compilation success: leafPubkey: ' + leafPubkey);

        //TODO: ECDSA-P256-SHA256-Verify( coseEccToSign, leafPubkey, manifestCoseEccSignature )
        logger.fatal('TODO: ampVerifyManifest error: incorrect ECC signature on manifest');

        // Verifying a Manifest Algorithm Step 10. Fail unless the certificate chain properly chains from leaf
        //                                         ( PemEncodedCertificates[0] ) to root via some chain path
        //                                         through the manifest-provided and input-provided certificates.

        //TODO: Hard-code the root cert to verify against
        //TODO: Verify cert chain manifest.publisherEvidence.pemEncodedCertificates[*]
        logger.fatal('TODO: ampVerifyManifest error: valid certificate chain could not be established');

        //logger.fatal('manifest is ' + JSON.stringify(manifest));
        verifiedManifests.push(msgdata);

        for (let i = 0; i < authenticators.length; i++) {
            verifiedAuthenticators.push(authenticators[i]);
        }

        return;
    }

    function findAmpHashData(data) {
        const isoFile = parse(data);

        if (!isoFile) {
            return;
        }

        const emsgs = isoFile.getBoxes('emsg');

        if (!emsgs) {
            logger.fatal('findAmpHashData error: no emsgs');
            return;
        }

        let emsg = null;
        for (let i = 0, ln = emsgs.length; i < ln; i++) {
            if (emsgs[i].scheme_id_uri === 'urn:mpeg:amp:chunk:emsg') {
                emsg = emsgs[i];
            }
        }

        if (!emsg) {
            logger.fatal('findAmpHashData error: no emsg with AMP chunk urn');
            return;
        }

        let message_data = emsg.message_data.buffer.slice(emsg.message_data.byteOffset, emsg.message_data.byteOffset + emsg.message_data.byteLength);
        let dataView = new DataView(message_data);
        let moov_id = dataView.getUint32(0);
        let track_id = dataView.getUint32(4);
        let sequence_number = dataView.getUint32(8);
        let hash_location = dataView.getUint16(12);
        let hash_size = dataView.getUint8(14);
        let hash_count = dataView.getUint8(15);

        logger.fatal('findAmpHashData - hash found' +
            ' ' + moov_id +
            ' ' + track_id +
            ' ' + sequence_number +
            ' ' + hash_location +
            ' ' + hash_size +
            ' ' + hash_count
        );

        let hashes = new Uint8Array(message_data.slice(16));
        if (hash_size !== 32) {
            logger.fatal('findAmpHashData error: hash size is not 32');
            return;
        }
        if (hashes.length !== hash_count * hash_size) {
            logger.fatal('findAmpHashData error: chunk data has the wrong size ' + hashes.length + ' vs ' + (hash_count * hash_size));
            return;
        }

        return;
    }

    instance = {
        parse: parse,
        findLastTopIsoBoxCompleted: findLastTopIsoBoxCompleted,
        getMediaTimescaleFromMoov: getMediaTimescaleFromMoov,
        getSamplesInfo: getSamplesInfo,
        findInitRange: findInitRange,
        ampVerifyManifest: ampVerifyManifest,
        findAmpHashData: findAmpHashData
    };

    setup();

    return instance;
}
BoxParser.__dashjs_factory_name = 'BoxParser';
export default FactoryMaker.getSingletonFactory(BoxParser);

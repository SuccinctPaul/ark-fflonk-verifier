#[cfg(test)]
mod test {
    use super::*;
    use std::str::FromStr;

    use crate::mock::{MOCK_PROOF_DATA, MOCK_PUB_INPUT};
    use crate::proof::Proof;
    use crate::verifier::fflonk_verifier;
    use crate::vk::{SnarkJSVK, VerificationKey};
    use ark_bn254::Fr;

    #[test]
    fn test_fflonk_verifier() {
        let pub_input = Fr::from_str(MOCK_PUB_INPUT).unwrap();

        let proof = Proof::construct(MOCK_PROOF_DATA.to_vec());

        let vk = VerificationKey::default();
        assert!(
            fflonk_verifier(&vk, &proof, &pub_input, false),
            "Proof verification failed!(is_recursive_verifier=false)"
        );
        assert!(
            fflonk_verifier(&vk, &proof, &pub_input, true),
            "Proof verification failed!(is_recursive_verifier=true)"
        );
    }

    #[test]
    fn test_verify_snarkjs_fflonk_proof() {
        let proof: Proof = serde_json::from_str(r#"
        {
            "protocol": "fflonk",
            "curve": "bn128",
            "polynomials": {
                "C1": [
                "19512952758028491405934790115790312944649901939821135923885427424035043432523",
                "14556573045681247107321758464038638460236603165915844088653795891137636966580",
                "1"
                ],
                "C2": [
                "18724765532860887462293740304560312103629598712675774059706825360379977966561",
                "14533846076669948037568538427127727867276686064060198244794640904541487914310",
                "1"
                ],
                "W1": [
                "18433064140714518735926988684235687309803035076187502211354351663568191930935",
                "14788057617464302331557630380512402745218864581677826595197645173223539673357",
                "1"
                ],
                "W2": [
                "16578902799151672151956332367598573028719537462531716854255433720543688684250",
                "21622823131302647207265406578951014306163648459064954245545121280505919027356",
                "1"
                ]
            },
            "evaluations": {
                "ql": "18137169988004520649554381379919736533761028898864355980977573474774839426808",
                "qr": "20404082766518508880627958927869090077251470748406210835504197196401842200720",
                "qm": "707461819326729660985337250976599267781706195992934524838013487904784094085",
                "qo": "18963438173828461591436352330653675208295853959010167304990158722672578932373",
                "qc": "0",
                "s1": "13524886271252282626956626393365051655320699188917745152708417704896009650580",
                "s2": "3174783679655029387130611916286066252438878675967458260277093528819580058722",
                "s3": "21577928273077063144453890504595174724360613180856082038860286291422143482499",
                "a": "10974786676655016445248972047105688770512999913871262036359224483296214498183",
                "b": "21083250626163147629372415164899163984499137689834405549506537520836126119194",
                "c": "18485668148010316467769714971633785148294508157898193267298903173050206942624",
                "z": "16553584390052184118636614382976559370280626167659817002054727638080918750406",
                "zw": "4415347360457194011128422992457486517452412864360300524180855069319812783387",
                "t1w": "14054646597435401354125275990480383598795508549938505679628793738166042203625",
                "t2w": "13096655044313949187605874896346306929343048005668253765142398343590307027689",
                "inv": "7456529870837358461413290055129561230845481425037098795678169994084881795519"
            }
        }
        "#).unwrap();
        let snarkjs_vk: SnarkJSVK = serde_json::from_str(
            r#"
        {
            "protocol": "fflonk",
            "curve": "bn128",
            "nPublic": 1,
            "power": 11,
            "k1": "2",
            "k2": "3",
            "w": "1120550406532664055539694724667294622065367841900378087843176726913374367458",
            "w3": "21888242871839275217838484774961031246154997185409878258781734729429964517155",
            "w4": "21888242871839275217838484774961031246007050428528088939761107053157389710902",
            "w8": "19540430494807482326159819597004422086093766032135589407132600596362845576832",
            "wr": "2369491970759584452636710321304902931967460429047736379260414030272612059905",
            "X_2": [
                [
                    "21831381940315734285607113342023901060522397560371972897001948545212302161822",
                    "17231025384763736816414546592865244497437017442647097510447326538965263639101"
                ],
                [
                    "2388026358213174446665280700919698872609886601280537296205114254867301080648",
                    "11507326595632554467052522095592665270651932854513688777769618397986436103170"
                ],
                [
                    "1",
                    "0"
                ]
            ],
            "C0": [
                "14083548345943606943399417459394802734806397334765586076624328254510003562122",
                "16034935275787414257017345944930967513154577770502614647348146024009658768590",
                "1"
            ]
        }
        "#,
        )
        .unwrap();
        let vk = snarkjs_vk.into();
        let pubs = Fr::from_str(
            "7713112592372404476342535432037683616424591277138491596200192981572885523208",
        )
        .unwrap();

        fflonk_verifier(&vk, &proof, &pubs, false);
    }
}

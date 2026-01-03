//! Complex miniscript parsing tests
//!
//! These tests verify that complex miniscript expressions parse correctly
//! and produce expected properties.

use super::common::init_testdata;
use miniscript_core_ffi::{Context, Miniscript};

#[test]
fn test_complex_miniscripts_part1() {
    init_testdata();

    // Test: lltvln:after(1231488000)
    let ms = Miniscript::from_str("lltvln:after(1231488000)", Context::Wsh);
    assert!(
        ms.is_ok() && ms.unwrap().is_valid(),
        "lltvln:after should be valid"
    );

    // Test: j:and_v(vdv:after(1567547623),older(2016))
    let ms = Miniscript::from_str("j:and_v(vdv:after(1567547623),older(2016))", Context::Wsh);
    assert!(
        ms.is_ok() && ms.unwrap().is_valid(),
        "j:and_v with after and older should be valid"
    );

    // Test: t:and_v with hash256 and sha256
    let ms = Miniscript::from_str(
        "t:and_v(vu:hash256(131772552c01444cd81360818376a040b7c3b2b7b0a53550ee3edde216cec61b),v:sha256(ec4916dd28fc4c10d78e287ca5d9cc51ee1ae73cbfde08c6b37324cbfaac8bc5))",
        Context::Wsh,
    );
    assert!(
        ms.is_ok() && ms.unwrap().is_valid(),
        "t:and_v with hashes should be valid"
    );

    // Test: or_d with sha256 and and_n
    let ms = Miniscript::from_str(
        "or_d(sha256(38df1c1f64a24a77b23393bca50dff872e31edc4f3b5aa3b90ad0b82f4f089b6),and_n(un:after(499999999),older(4194305)))",
        Context::Wsh,
    );
    assert!(
        ms.is_ok() && ms.unwrap().is_valid(),
        "or_d with sha256 and timelocks should be valid"
    );

    // Test: and_b with older and or_d
    let ms = Miniscript::from_str(
        "and_b(older(16),s:or_d(sha256(e38990d0c7fc009880a9c07c23842e886c6bbdc964ce6bdd5817ad357335ee6f),n:after(1567547623)))",
        Context::Wsh,
    );
    assert!(
        ms.is_ok() && ms.unwrap().is_valid(),
        "and_b with older and or_d should be valid"
    );

    // Test: j:and_v with hash160 and or_d
    let ms = Miniscript::from_str(
        "j:and_v(v:hash160(20195b5a3d650c17f0f29f91c33f8f6335193d07),or_d(sha256(96de8fc8c256fa1e1556d41af431cace7dca68707c78dd88c3acab8b17164c47),older(16)))",
        Context::Wsh,
    );
    assert!(
        ms.is_ok() && ms.unwrap().is_valid(),
        "j:and_v with hash160 should be valid"
    );

    // Test: and_b with two hash256
    let ms = Miniscript::from_str(
        "and_b(hash256(32ba476771d01e37807990ead8719f08af494723de1d228f2c2c07cc0aa40bac),a:and_b(hash256(131772552c01444cd81360818376a040b7c3b2b7b0a53550ee3edde216cec61b),a:older(1)))",
        Context::Wsh,
    );
    assert!(
        ms.is_ok() && ms.unwrap().is_valid(),
        "and_b with hash256 should be valid"
    );

    // Test: and_n with sha256 and or_i
    let ms = Miniscript::from_str(
        "and_n(sha256(d1ec675902ef1633427ca360b290b0b3045a0d9058ddb5e648b4c3c3224c5c68),t:or_i(v:older(4252898),v:older(144)))",
        Context::Wsh,
    );
    assert!(
        ms.is_ok() && ms.unwrap().is_valid(),
        "and_n with sha256 and or_i should be valid"
    );

    // Test: or_d with nested and_v
    let ms = Miniscript::from_str(
        "or_d(nd:and_v(v:older(4252898),v:older(4252898)),sha256(38df1c1f64a24a77b23393bca50dff872e31edc4f3b5aa3b90ad0b82f4f089b6))",
        Context::Wsh,
    );
    assert!(
        ms.is_ok() && ms.unwrap().is_valid(),
        "or_d with nested and_v should be valid"
    );

    // Test: and_v with andor
    let ms = Miniscript::from_str(
        "and_v(andor(hash256(8a35d9ca92a48eaade6f53a64985e9e2afeb74dcf8acb4c3721e0dc7e4294b25),v:hash256(939894f70e6c3a25da75da0cc2071b4076d9b006563cf635986ada2e93c0d735),v:older(50000)),after(499999999))",
        Context::Wsh,
    );
    assert!(
        ms.is_ok() && ms.unwrap().is_valid(),
        "and_v with andor should be valid"
    );

    // Test: andor with hash256, j:and_v, and ripemd160
    let ms = Miniscript::from_str(
        "andor(hash256(5f8d30e655a7ba0d7596bb3ddfb1d2d20390d23b1845000e1e118b3be1b3f040),j:and_v(v:hash160(3a2bff0da9d96868e66abc4427bea4691cf61ccd),older(4194305)),ripemd160(44d90e2d3714c8663b632fcf0f9d5f22192cc4c8))",
        Context::Wsh,
    );
    assert!(
        ms.is_ok() && ms.unwrap().is_valid(),
        "andor with multiple hashes should be valid"
    );
}

#[test]
fn test_complex_miniscripts_part2() {
    init_testdata();

    // Test: or_i with c:and_v and sha256
    let ms = Miniscript::from_str(
        "or_i(c:and_v(v:after(500000),pk_k(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)),sha256(d9147961436944f43cd99d28b2bbddbf452ef872b30c8279e255e7daafc7f946))",
        Context::Wsh,
    );
    assert!(
        ms.is_ok() && ms.unwrap().is_valid(),
        "or_i with after and sha256 should be valid"
    );

    // Test: thresh with pk_h, sha256, and hash160
    let ms = Miniscript::from_str(
        "thresh(2,c:pk_h(025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc),s:sha256(e38990d0c7fc009880a9c07c23842e886c6bbdc964ce6bdd5817ad357335ee6f),a:hash160(dd69735817e0e3f6f826a9238dc2e291184f0131))",
        Context::Wsh,
    );
    assert!(
        ms.is_ok() && ms.unwrap().is_valid(),
        "thresh with pk_h and hashes should be valid"
    );

    // Test: and_n with sha256 and uc:and_v
    let ms = Miniscript::from_str(
        "and_n(sha256(9267d3dbed802941483f1afa2a6bc68de5f653128aca9bf1461c5d0a3ad36ed2),uc:and_v(v:older(144),pk_k(03fe72c435413d33d48ac09c9161ba8b09683215439d62b7940502bda8b202e6ce)))",
        Context::Wsh,
    );
    assert!(
        ms.is_ok() && ms.unwrap().is_valid(),
        "and_n with sha256 and uc:and_v should be valid"
    );

    // Test: and_n with c:pk_k and and_b
    let ms = Miniscript::from_str(
        "and_n(c:pk_k(03daed4f2be3a8bf278e70132fb0beb7522f570e144bf615c07e996d443dee8729),and_b(l:older(4252898),a:older(16)))",
        Context::Wsh,
    );
    assert!(
        ms.is_ok() && ms.unwrap().is_valid(),
        "and_n with pk_k and and_b should be valid"
    );

    // Test: c:or_i with and_v and pk_h
    let ms = Miniscript::from_str(
        "c:or_i(and_v(v:older(16),pk_h(02d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e)),pk_h(026a245bf6dc698504c89a20cfded60853152b695336c28063b61c65cbd269e6b4))",
        Context::Wsh,
    );
    assert!(
        ms.is_ok() && ms.unwrap().is_valid(),
        "c:or_i with and_v should be valid"
    );

    // Test: or_d with c:pk_h and andor
    let ms = Miniscript::from_str(
        "or_d(c:pk_h(02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13),andor(c:pk_k(024ce119c96e2fa357200b559b2f7dd5a5f02d5290aff74b03f3e471b273211c97),older(2016),after(1567547623)))",
        Context::Wsh,
    );
    assert!(
        ms.is_ok() && ms.unwrap().is_valid(),
        "or_d with pk_h and andor should be valid"
    );

    // Test: c:andor with ripemd160, pk_h, and and_v
    let ms = Miniscript::from_str(
        "c:andor(ripemd160(6ad07d21fd5dfc646f0b30577045ce201616b9ba),pk_h(02d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e),and_v(v:hash256(8a35d9ca92a48eaade6f53a64985e9e2afeb74dcf8acb4c3721e0dc7e4294b25),pk_h(03d01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85a)))",
        Context::Wsh,
    );
    assert!(
        ms.is_ok() && ms.unwrap().is_valid(),
        "c:andor with ripemd160 should be valid"
    );

    // Test: c:andor with u:ripemd160 and or_i
    let ms = Miniscript::from_str(
        "c:andor(u:ripemd160(6ad07d21fd5dfc646f0b30577045ce201616b9ba),pk_h(03daed4f2be3a8bf278e70132fb0beb7522f570e144bf615c07e996d443dee8729),or_i(pk_h(022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01),pk_h(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)))",
        Context::Wsh,
    );
    assert!(
        ms.is_ok() && ms.unwrap().is_valid(),
        "c:andor with u:ripemd160 should be valid"
    );

    // Test: c:or_i with nested andor
    let ms = Miniscript::from_str(
        "c:or_i(andor(c:pk_h(03d30199d74fb5a22d47b6e054e2f378cedacffcb89904a61d75d0dbd407143e65),pk_h(022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01),pk_h(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)),pk_k(02d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e))",
        Context::Wsh,
    );
    assert!(
        ms.is_ok() && ms.unwrap().is_valid(),
        "c:or_i with nested andor should be valid"
    );

    // Test: thresh with c:pk_k and altv:after
    let ms = Miniscript::from_str(
        "thresh(1,c:pk_k(03d30199d74fb5a22d47b6e054e2f378cedacffcb89904a61d75d0dbd407143e65),altv:after(1000000000),altv:after(100))",
        Context::Wsh,
    );
    assert!(
        ms.is_ok() && ms.unwrap().is_valid(),
        "thresh with altv:after should be valid"
    );

    // Test: thresh with two c:pk_k and two altv:after
    let ms = Miniscript::from_str(
        "thresh(2,c:pk_k(03d30199d74fb5a22d47b6e054e2f378cedacffcb89904a61d75d0dbd407143e65),ac:pk_k(03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556),altv:after(1000000000),altv:after(100))",
        Context::Wsh,
    );
    assert!(
        ms.is_ok() && ms.unwrap().is_valid(),
        "thresh with 2 keys and 2 timelocks should be valid"
    );
}

#[test]
fn test_multi_signature_constructions() {
    init_testdata();

    // Test various multi-signature constructions
    let ms = Miniscript::from_str(
        "uuj:and_v(v:multi(2,03d01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85a,025601570cb47f238d2b0286db4a990fa0f3ba28d1a319f5e7cf55c2a2444da7cc),after(1231488000))",
        Context::Wsh,
    );
    assert!(
        ms.is_ok() && ms.unwrap().is_valid(),
        "multi with and_v should be valid"
    );

    let ms = Miniscript::from_str(
        "or_b(un:multi(2,03daed4f2be3a8bf278e70132fb0beb7522f570e144bf615c07e996d443dee8729,024ce119c96e2fa357200b559b2f7dd5a5f02d5290aff74b03f3e471b273211c97),al:older(16))",
        Context::Wsh,
    );
    assert!(
        ms.is_ok() && ms.unwrap().is_valid(),
        "or_b with multi should be valid"
    );

    let ms = Miniscript::from_str(
        "t:andor(multi(3,02d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e,03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556,02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13),v:older(4194305),v:sha256(9267d3dbed802941483f1afa2a6bc68de5f653128aca9bf1461c5d0a3ad36ed2))",
        Context::Wsh,
    );
    assert!(
        ms.is_ok() && ms.unwrap().is_valid(),
        "andor with multi(3) should be valid"
    );

    let ms = Miniscript::from_str(
        "or_d(multi(1,02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9),or_b(multi(3,022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01,032fa2104d6b38d11b0230010559879124e42ab8dfeff5ff29dc9cdadd4ecacc3f,03d01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85a),su:after(500000)))",
        Context::Wsh,
    );
    assert!(
        ms.is_ok() && ms.unwrap().is_valid(),
        "or_d with nested multi should be valid"
    );

    let ms = Miniscript::from_str(
        "and_v(or_i(v:multi(2,02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5,03774ae7f858a9411e5ef4246b70c65aac5649980be5c17891bbec17895da008cb),v:multi(2,03e60fce93b59e9ec53011aabc21c23e97b2a31369b87a5ae9c44ee89e2a6dec0a,025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc)),sha256(d1ec675902ef1633427ca360b290b0b3045a0d9058ddb5e648b4c3c3224c5c68))",
        Context::Wsh,
    );
    assert!(
        ms.is_ok() && ms.unwrap().is_valid(),
        "and_v with or_i of multis should be valid"
    );

    let ms = Miniscript::from_str(
        "j:and_b(multi(2,0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,024ce119c96e2fa357200b559b2f7dd5a5f02d5290aff74b03f3e471b273211c97),s:or_i(older(1),older(4252898)))",
        Context::Wsh,
    );
    assert!(
        ms.is_ok() && ms.unwrap().is_valid(),
        "j:and_b with multi should be valid"
    );

    let ms = Miniscript::from_str(
        "thresh(2,multi(2,03a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7,036d2b085e9e382ed10b69fc311a03f8641ccfff21574de0927513a49d9a688a00),a:multi(1,036d2b085e9e382ed10b69fc311a03f8641ccfff21574de0927513a49d9a688a00),ac:pk_k(022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01))",
        Context::Wsh,
    );
    assert!(
        ms.is_ok() && ms.unwrap().is_valid(),
        "thresh with multiple multis should be valid"
    );

    let ms = Miniscript::from_str(
        "c:and_v(or_c(sha256(9267d3dbed802941483f1afa2a6bc68de5f653128aca9bf1461c5d0a3ad36ed2),v:multi(1,02c44d12c7065d812e8acf28d7cbb19f9011ecd9e9fdf281b0e6a3b5e87d22e7db)),pk_k(03acd484e2f0c7f65309ad178a9f559abde09796974c57e714c35f110dfc27ccbe))",
        Context::Wsh,
    );
    assert!(
        ms.is_ok() && ms.unwrap().is_valid(),
        "c:and_v with or_c and multi should be valid"
    );

    let ms = Miniscript::from_str(
        "c:and_v(or_c(multi(2,036d2b085e9e382ed10b69fc311a03f8641ccfff21574de0927513a49d9a688a00,02352bbf4a4cdd12564f93fa332ce333301d9ad40271f8107181340aef25be59d5),v:ripemd160(1b0f3c404d12075c68c938f9f60ebea4f74941a0)),pk_k(03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556))",
        Context::Wsh,
    );
    assert!(
        ms.is_ok() && ms.unwrap().is_valid(),
        "c:and_v with or_c multi(2) should be valid"
    );
}

#[test]
fn test_additional_timelock_tests() {
    init_testdata();

    // Test: after(100) - only heightlock
    let ms = Miniscript::from_str("after(100)", Context::Wsh);
    assert!(
        ms.is_ok() && ms.unwrap().is_valid(),
        "after(100) heightlock should be valid"
    );

    // Test: after(1000000000) - only timelock
    let ms = Miniscript::from_str("after(1000000000)", Context::Wsh);
    assert!(
        ms.is_ok() && ms.unwrap().is_valid(),
        "after(1000000000) timelock should be valid"
    );

    // Test: thresh with timelock mixing (valid but has timelock mix)
    let ms = Miniscript::from_str(
        "thresh(2,ltv:after(1000000000),altv:after(100),a:pk(03d30199d74fb5a22d47b6e054e2f378cedacffcb89904a61d75d0dbd407143e65))",
        Context::Wsh,
    );
    assert!(
        ms.is_ok() && ms.unwrap().is_valid(),
        "thresh with timelock mix should be valid"
    );

    // Test: thresh with k=1 and mixed timelocks
    let ms = Miniscript::from_str(
        "thresh(1,c:pk_k(03d30199d74fb5a22d47b6e054e2f378cedacffcb89904a61d75d0dbd407143e65),altv:after(1000000000),altv:after(100))",
        Context::Wsh,
    );
    assert!(
        ms.is_ok() && ms.unwrap().is_valid(),
        "thresh k=1 with timelocks should be valid"
    );
}

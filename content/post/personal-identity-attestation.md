---
title: "Personal Identity Attestation"
date: 2019-07-17T21:21:03-07:00
draft: false
---

I'm here to jump on the "PGP is bad" bandwagon. I recently read "[The PGP
Problem](https://latacora.micro.blog/2019/07/16/the-pgp-problem.html)", a blog
post all about how PGP is an aged, bizarre, yet still incredibly relevant piece
of personal identity software. I'm not going to rehash the points that are made
in that post. It is a really good post, you should read it if you haven't -- not
only because what I'll write after is an extension of this post, but also
because its some great content.

I use PGP semi-regularly. I don't use it correctly, but I use it as a cool hook
in to some of the other work I do in my life. For example, did you know that you
can set up Git so that it automatically signs each commit and tag by default?
Then when you push up your commits to Github, Github rubber stamps your commit
with the wonderful seal of approval - a green verified sticker on each commit,
telling the world about how you did the security.

![Github showing that my 'Add some much needed newlines!' commit is
verified](../../images/github_verified_badge.png)

Obviously I'm skipping over the massive security benefits commit signing brings.
Git repositories (from large repository sites like Github to even a local file
system repository) decouple authentication for submitting commits to a
repository from actually generating the commits, allowing for situations where
someone with push access to a repository could push up "someone else's" commits
without anyone the wiser. No Git project would work without it - symmetric
access to all different versions of a Git repository would destroy the very
distributed nature that Git strives for. This very behavior then requires
contributers to cryptographically sign their commits - this enforces that no
matter how the commit gets handed about, the contributor's key pair attests that
the commit contains the same content it had when originally signed.

I don't write important enough OSS to warrant me needing to sign _every single
commit_. My most popular project
[NuVotifier](https://github.com/nuvotifier/nuvotifier) has under 42k downloads
over its entire lifetime and is used by Minecraft servers to process network
connections from server lists. If that means nothing to you, thats okay. It
doesn't have to. Since I'm the main contributer, I sign each commit. However,
does it really matter that I sign each commit? Is someone watching the commit
chain for each release, making sure that all of the code is legitimately from
me? No. I don't bother signing the releases, which is how the vast majority of
users get NuVotifier. And even if I did, I doubt anyone would even check.

Truth is, I sign my commits because one day I found the PGP key option in my
Github settings and I was motivated by each of my commits having the green
sticker. It made it look 'better'. Which hey, in all fairness it was, but I'm
not convinced for the scale of the software I write matters.

I've seen one project which actually uses Git+PGP in an interesting and
effective way. [dn42's
registry](https://dn42.net/howto/Getting-started#formalities_fill-in-the-registry_create-a-maintainer-object)
is authenticated through PGP on Git commits. Commits which modify objects which
are maintained by a maintainer with a pgp-fingerprint must be signed with the
key with said pgp-fingerprint. It satisfies the security that I describe two
paragraphs above and suits dn42's needs wonderfully - open access to all data
within the dn42 registry without needing to trust dn42 to enforce security.

I've talked about PGP in a code context this whole time when PGP is obviously
much more flexible than code. However, that is the only context which I have
really interacted with PGP. PGP is also used for email, however I think it is
completely agreeable that modern email in the public eye has pretty much ignored
PGP. So really, PGP boils down to signing code.

I said above I don't use PGP correctly. If I were to be using PGP correctly, I
would take web-of-trust far more seriously than just downloading keys off the
Internet so that ArchLinux stops complaining about unknown keys when updating.
I'm definitely part of the problem here. I mean, who even are these people?!

![Some random people I added trust for so ArchLinux would stop being cranky at
me](../../images/who_are_you_people_pgp.png)

However, how feasible is web-of-trust really? I'm a young person, and I really
don't have time or money to go fly across the country or world to meet the
people who sign the packages I depend on. And sure, in a web-of-trust system, I
don't have to do that. But a web-of-trust suggests that the people I trust most
would instead have that ability, and the transitive trust through my well
trusted acquaintance would give me the ability to then trust other people. The
only problem is that my friends who I trust are also young and don't have the
money or time (or the interest!) to go to key signing parties.

The PGP Problem mentions
[signify](https://www.openbsd.org/papers/bsdcan-signify.html), a tool to sign
binary blobs with keys. Painfully simple, all it does is sign and verify
signatures which is great if all that needs to be done is sign packages with a
single signature. Signify rips out all of the bookkeeping of storing keys - all
keys are simply stored in files on disk in a base64 encoded format. There is no
additional metadata about a key - its just a key. Speaking of a key, here is my
key:

![My signify public key:
RWRIxAF+aqAZWqyhJUNPwx6tqFAJSRWGZlHtfkqITc+qKZg82eqQcyVc](../../images/signify.pub.png)

I think signify is great for what it is, and while I'm not a signing party
fanatic as mentioned above, curating of keys with associated metadata that third
party tools can use seems pretty nice. Obviously I'm going to skip by verifying
completely who is on the other end of a key, but having a name stapled to a key
just feels correct. Maybe this is just PGP normalizing my thinking on the PGP
way of doing key management, but I think signify misses this for being a general
purpose identity verification tool. That being said, signify never signed up to
be a general purpose identity management tool.

Keybase is an interesting service that seems to hit at least two of my problems
above - keybase provides key-identity pinning (you can associate many pieces of
information with your keybase identity, such as on-line accounts, domain names,
associated cryptocurrency public keys) as well as a simple to use web-of-trust
'following' system. Keybase's web-of-trust system seems incredibly similar to
PGP's keysigning party concept, however instead of needing to directly verify
identity, I can get away with indirectly verifying identity via a third party
service and the public attestation system that Keybase has come up with. Through
[this gist](https://gist.github.com/Ichbinjoe/53f718ea4427ab8f3cdf), I stated
that I am Ichbinjoe on Github.

To add to the value of Keybase, Keybase is developing tooling around their
identity verification system, introducing products which compete with the likes
of Slack with their Keybase teams offering and Google Drive/Dropbox with the
public and private mountable folders. Keybase offers more services (and no doubt
is making more services to continue to bring identity cryptography to the
masses) than what I mentioned, but no solution comes without faults. My big
issue with Keybase is that realistically Keybase can't exist without Keybase. At
the end of the day, Keybase is a service which depends on the existence of
itself. By simply relying on itself, Keybase is sitting as a third party to what
otherwise is a strictly two party system. While Keybase's (the service)
doesn't need to attest to a third party profile linkage to a Keybase profile
(all of those linkages are based on external verification proofs), these
linkages are practically only discoverable through Keybase itself - without
Keybase's existence, does the linkage really matter?

All that to say, your profile lives on Keybase. If Keybase stops Keybasing (I
can't figure out how to pay for it!) then it doesn't really matter anyways.

I could talk about Signal and in general application specific cryptography in
some depth, but in short there are two important take-aways as far as I am
concerned. First, Signal specifically implements some sort of key rotation. Key
rotation is simply best practice - you should do it. However, the above tools
make key rotation a manual process. I recently switched my expiring PGP key to a
non-expiring PGP key out of fear that the key would expire before I could attest
that I was changing my key, so you can see how well that whole key rotation
thing went. Key rotation is great, but really needs to be designed into the
cryptographic system. Key rotation isn't designed into signify because its
handled at a higher level (see the signify post if you want to learn more). Key
rotation in PGP is simply a pain - its a very manual process where you cross
sign both the old and new key, revoke the old key, then upload all to a
keyserver and wait for the rest of the world to then download said key from the
keyserver again. Maybe there is a simpler way to do this - I wouldn't know. The
downside of using applications like Signal is that Signal can only be used to do
Signally things - its a messenger at heart, and isn't good at being used for
implementing thing like signing of code.

No, I don't have some answer to this whole mess we are in. It doesn't seem like
anyone else does either, considering there is no real prominent solution out in
the world. I could imagine some sort of federated Keybase being successful with
proper _existing_ tool integrations and multiple platform support. Unfortunately
I don't have the time to create such a system. Here's to hoping someone does.

# Federation example

This set of directories allows you to set up 2 federations, together
containing a Wallet Provider, a PID Issuer, a (Q)EAA issuer, two intermediates
and a trust anchor (TA).

The two intermediates (**issuer** and **provider**) are immediate subordinates to the TA.
The Trust Mark Issuer is also an immediate subordinate to the TA.

**Issuer** intermediate has two subordinate, the PID and (Q)EAA issuers.
The **provider** intermediate has one subordinates; the Wallet Provider.

# Setting up the test federations

There is a set of information that must be the same in different places in
the setup. All the superiors must know the entity_id and the federation keys of
its subordinates. I would also benefit from knowing the entity types of its subordinates
and if they in their turn are intermediates.

All of this can be accomplished by using the script `setup.py`. 

`setup.py` **MUST** be run before you attempt to start the entities. 

`setup.py` will create files in the entities directories.

# Testing and verifying the example federation

## Starting/stopping entities

For the commands below to work you are supposed to
stand in the fedservice/example/entities directory.

A simple script for starting/stopping entities:

    ./exec.py start wp pid qeaa issuer provider tmi dc4eu

This will start all entities in the example federations.
If you want to look at the layout of the federation look at the 
_Federation Example.jpg_ file.

The different entities are:

    wp
        A Wallet Provider
    pid
        A Personal Identification Data Issuer
    qeaa
        A (Q)EAA Issuer
    provider
        An intermediate maneging wallet providers
    issuer
        An intermediate managing credential issuers
    tmi
        A Trust Mark Issuer
    dc4eu
        The Trust Anchor.

Stopping an entity is as simple as starting it:

    ./exec.py kill wp

The above command will kill only the Wallet Provider (wp) entity.

## Displaying an entity's entity statement

The entity_ids for the different entities are:

    wp
        https://127.0.0.1:5000
    pid 
        https://127.0.0.1:5001
    qeaa
        https://127.0.0.1:5002
    tmi
        https://127.0.0.1:5003
    issuer
        https://127.0.0.1:6000
    provider
        https://127.0.0.1:6001
    dc4eu
        https://127.0.0.1:7000

For this you can use the `display_entity.py` script:

    ./display_entity.py https://127.0.0.1:5000

Will display the Entity Configuration of the entity that has the provided entity_id.
If the entity is an intermediate or trust anchor, that is has subordinates,
it will also list the subordinates. 
As **provider** is the superior of the Wallet Provider (wp) if you do:

    ./display_entity.py https://127.0.0.1:6001

You will get a list of 2 entities: https://127.0.0.1:6001 (provider)
and https://127.0.0.1:5000 (wp).

## Parsing trust chains.

To do this you use `get_chains.py`

    ../script/get_chains.py -k -t trust_anchors.json https://127.0.0.1:5000

* -k : Don't try to verify the certificate used for TLS
* -t : A JSON file with a dictionary with trust anchors and their keys.
* The entity ID of the target

This will list the entity statements of the entities in the collected trust 
chains. Each list will start with the trust anchor and then list the
intermediates and finally the leaf in that order.

If you do:

    ./exec.py start wp provider dc4eu
    ../script/get_chains.py -k -t trust_anchors.json https://127.0.0.1:5000

You will see one list with 3 entities in it.

One can also play around with `get_entity_statement.py`

usage: get_entity_statement.py [-h] [-k] [-t TRUST_ANCHORS_FILE] [-c] [-s SUPERIOR] entity_id

positional arguments:
    entity_id

    options:

    -h, --help            show this help message and exit
    -k, --insecure 
    -t TRUST_ANCHORS_FILE, --trust_anchors_file TRUST_ANCHORS_FILE
    -c
    -s SUPERIOR, --superior SUPERIOR

and an example:

../script/get_entity_statement.py -k -c -t trust_anchors.json -s https://127.0.0.1:6001 
https://127.0.0.1:5000

This will first display the Entity Configuration for https://127.0.0.1:5000
and then the Entity Statement for https://127.0.0.1:5000 as produced by
https://127.0.0.1:6001
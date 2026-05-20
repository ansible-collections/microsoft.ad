# microsoft.ad.domain_trust tests

As this cannot be run in CI this is a brief guide on how to run these tests locally.
Run the following:

```bash
vagrant up

ansible-playbook setup.yml
```

It is a good idea to create a snapshot of both hosts before running the tests.
This allows you to reset the host back to a blank starting state if the tests need to be rerun.
To create a snapshot do the following:

```bash
virsh snapshot-create-as --domain "domain_trust_DC1" --name "pretest"
virsh snapshot-create-as --domain "domain_trust_DC2" --name "pretest"
```

To restore these snapshots run the following:

```bash
virsh snapshot-revert --domain "domain_trust_DC1" --snapshotname "pretest" --running
virsh snapshot-revert --domain "domain_trust_DC2" --snapshotname "pretest" --running
```

Once you are ready to run the tests run the following:

```bash
ansible-playbook test.yml
```

Run `vagrant destroy` to remove the test VMs.

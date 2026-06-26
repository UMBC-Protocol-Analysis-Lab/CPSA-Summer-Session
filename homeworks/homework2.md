# Homework 2

## Instructions
Now that you have a little bit more practice with using CPSA, let's explore how we spot attacks using CPSA.
In the directory [homework2files](homework2files) you will find several models.
Models 1 and 2 are complete, while Models 4 and 5 have a *fill-in-the-blank* portion that you must complete before you can run the model.
If you would like an extra challenge, Models 2 and 3 have optional *fill-in-the-blank* files labelled as "challenges".
For each model, check if it is complete and complete it if not.
Then run CPSA and take a look at the shapes file, `problem_n_shapes.xhtml`.
In each shapes file, identify if the protocol is compromised, and what action(s) the adversary has taken to create the attack.

Remember that the adversary can:
1. Create a message
2. Split apart messages
3. Concatenate messages
4. Generate its own key for cryptographic operations
5. Encrypt using any key available to it
6. Decrypt using any key available to it
7. Hash using the public hash function

The adversary can also support many simultaneous executions of the protocol simultaneously.

## Deliverable
1. Models that were not complete before completed
	1. Submit your completed `*.scm` files for models that you filled in.
2. A writeup of whether each of the five protocols is secure or not, and if not secure, what the adversary has done to create the attack.
    1. Submit your brief writeup. Please use complete sentences.
  
## Submission
Please submit your protocol via this google form:
https://docs.google.com/forms/d/e/1FAIpQLSd7tsWjraZPH2moERTXZWKyoNFABfWbMH2KVfZj6yYHBFIakg/viewform

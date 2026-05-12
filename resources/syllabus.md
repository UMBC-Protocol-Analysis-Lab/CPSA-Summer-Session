# Preliminaries

This is a workshop series on cryptography, proofs in cryptographic protocols, analysis of protocols, and adversarial thinking. This series does not cover cybersecurity in the conventional sense, we do not discuss implementations of protocols/coding or IT practices for cybersecurity, though those are equally important when considering secure systems. We use a programming language called [Cryptographic Protocols Shapes Analyzer (CPSA)](https://github.com/mitre/cpsa4) to model protocols. The goal of this workshop is to introduce participants to cybersecurity research, including the work done by the [UMBC Protocol Analysis Lab](https://github.com/UMBC-Protocol-Analysis-Lab). We introduce and discuss several real projects that the lab has worked on, many of which have resulted in publications at prestigious conferences and journals.

# Learning Objectives

By the end of the workshop, students should be able to:
1. Understand and reason about basic cryptographic protocol **components**, including: *strands, keys, encryption, decryption, hashing, messages,* and *protocols*. Students will also learn about who the adversary is
   1. By the end of the first session,
      1. students will be able to explain protocol components, including: *strands, keys, encryption, decryption, hashing, messages,* and *protocols*.
      2. Students will be able to name the adversary.
   2. By the end of the second session,
      1. Students will be able to describe the adversary
      2. Students will be able to assemble protocol components into real protocols
2. Use CPSA to model protocols based on specifications and identify problems;
   1. By the end of the third session,
      1. Students will be able to describe an attack that CPSA has identified.
   2. By the end of the fourth session, students will be able to model simple protocols in CPSA and identify the components of CPSA shapes
3. Read and understand protocol specifications for real-world protocols;
   1. By the end of the fifth session,
      1. Students will be able to read and understand basic protocol specifications, and produce CPSA models from these basic specifications
      2. Students will be able to model more complex protocols in CPSA from a given diagram.
      3. Students will be able to interpret shapes in the adversarial model.
   2. By the end of the sixth session,
      1. Students will understand the use of CPSA’s goal syntax to model protocols with specified security goals.
      2. Students will be able to read and understand full protocol specifications, and produce CPSA models from a full specification
4. Understand and reason about mathematical formalism used by CPSA.
   1. By the end of the seventh session,
      1. Students will be able to find information about CPSA’s mathematical basis
      2. Students will be able to name and briefly describe modern post-quantum protocols
   2. By the end of the eighth session, students will be able to present on a general protocol from a given a specification, including: how they have modeled the protocol using CPSA, and what attacks CPSA has identified

# Methods

Students will accomplish the learning objectives by:
1. Attending synchronous training sessions twice per week for one hour
2. Completing CPSA homework assignments relating to training sessions
3. Reading and understanding protocol specifications during training sessions and as a part of the homeworks

# Instructors

### Michael Barthel
**BIO**:
Michael Barthel is a current undergraduate student from UMBC pursuing a dual degree in Computer Science and Accounting.
He has been a member of the Protocol Analysis Lab for just under a year, during which he has both helped with CPSA training sessions in the lab and worked to become a co-author on PAL's most recent paper.

**Contact**: \
Discord: notthatpurevessel \
Email: mbarthe1 at umbc dot edu

### DeMarko Fulcher
**BIO**:
DeMarko Fulcher has graduated from UMBC, with a B.S. in Mathematics, he is currently pursuing a M.S. in Computer Science at UMBC.
He is a part of the ATOMS Lab, E-WiNS Lab and Protocol Analysis Lab where he focuses on formal methods, automated reasoning, and security research. Previously, he has assisted with the training sessions for learning Cryptography Protocol Shapes Analyzer (CPSA).

**Contact**: \
Discord: mark_math \
Email: demarkf1 at umbc dot edu

### Sai Matukumalli
**BIO**:
Sai Matukumalli has graduated from UMBC, with degrees in both computer science and mathematics.
He has been a member of the Protocol Analysis Lab for approximately two years, and has previously led CPSA training sessions during the semester.
He mainly works on mathematical cryptography and algorithms.

**Contact**: \
Discord: saikmat \
Email: smatuku1 at umbc dot edu

### Jeremy Romano
**BIO**:
Jeremy Romano has graduated from UMBC with a degree in Computer Science.
He has been a member of the Protocol Analysis Lab for approximately three years, and has previously led CPSA training sessions during the semester.
He mainly works on secure system administration.

**Contact**: \
Discord: zasderjjrr123 \
Email: jeremyr1 at umbc dot edu

# Workshop expectations

The workshop is relatively intensive because we have limited time.
We expect participants to attend the majority of synchronous meetings (1 hour long on **FILL IN DATE HERE**), or at least to watch the recordings if they are unable to attend.
Be prepared to spend between one and three hours to complete the homework assignments.
Tuesday assignments will be easier to complete, since there is less time to do them, thursday assigments will generally be more complicated.
If you have questions, please feel free to reach out to one of us over Discord or email, we are here to help!

**AI Policy:** ChatGPT does not have enough training data to write CPSA code, and you are here to learn anyway, so you will not need to use AI.
You are welcome to try and use AI, if you succeed please let us know, we're curious too!

# Homework

There will be 5 homeworks assigned during this series to facilitate learning how to write models in CPSA. 
We recognize that this is a summer activity, and you probably don't want to do homework, but the best way to learn a new tool is practice, and we simply do not have time to code during synchronous meetings.

For a detailed schedule of when there will be homeworks, see the [Schedule](#Schedule). Assignments themselves will be posted in the [Homeworks](../homeworks) directory.

# Final Project

There is a final project that will put all of your cybersecurity and CPSA skills to the test, and is a good metric of the kind of work we do in the lab. The final project will be given out at the end of week 3, and is to be presnted at the end of the series. Details on the final project can be found at the [Final project readme](../final_project/final_project.md).

# Schedule

The workshop series will have synchronous meetings twice a week for 4 weeks, a total of 8 meetings. Meetings run from May 26 to June 18, and occur on **Tuesdays and Thursdays from 6PM to 7PM**. The first several lectures include foundational cryptography concepts. Each week is generally separated into an introductory lecture on theory, and then a lecture on CPSA and applications.

## Week 1

### Session 1

- What is a protocol
- Cryptography intro
- Dolev-Yao adversary
- Adversary actions (crypto primitives)
- Designing a meeting protocol on whiteboard
- [Homework 1](../homeworks/homework1.md): Design a protocol of your own (for another scenario)

### Session 2

- Strand spaces
- Needham-Schroeder protocol
- Protocol analysis
- CPSA tutorial for protocol analysis
- [Homework 2](../homeworks/homework2.md): Improve your protocol by using CPSA

## Week 2

### Session 1

- Spotting attacks in CPSA
- Fixing attacks in CPSA
- Model example program in CPSA
- Maybe something other than PAKE-0? (PAKE unless good alternative)
- [Homework 3](../homeworks/homework3.md): Model several â€œknown-badâ€ protocols that we design, and use CPSA to identify the flaw(s)

### Session 2

- Needham-Schroeder Key Exchange
- Assumptions in CPSA
- Channels in CPSA
- [Homework 4](../homeworks/homework4.md):
  - FIDO

## Week 3

### Session 1

LO 3a: By the end of the fifth session, students will be able to model more complex protocols in CPSA, and understand what shapes mean when analyzing them

- Diffie-Hellman Key Exchange
- Practical application, show SecureDNA and all the work needed both within and outside of CPSA
- [Homework 5](../homeworks/homework5.md): Model simplified SecureDNA

### Session 2

- Mathematical crypto
- Real proofs for CPSA
- Assign [final project](../final_project/final_project.md)

## Week 4

### Session 1

- Maybe about the future of crypto, maybe post-quantum?
- Ask for help on final project

### Session 2

- Present final project


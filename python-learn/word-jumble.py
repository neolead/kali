# word jumble

import random

WORDS = ("python", "jumble", "easy", "difficult", "answer", "xylophone")

word = random.choice(WORDS)

correct = word
jumble = ""
while word != "":
    position = random.randrange(len(word))
    jumble += word[position]
    word = word[:position] + word[position + 1:]

print("the jumble is ", jumble)

guess = raw_input("please guess:")

count = 0
times = 3
while guess != correct and count != times:
    guess = raw_input("wrong, guess again:")
    count += 1

if guess == correct:
    print("OK, YOU WIN")
else:
    print("SORRY, YOU WRONG THREE TIMES")

raw_input("\n input enter to exit")

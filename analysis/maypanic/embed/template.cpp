#include <algorithm>
#include <deque>
#include <iostream>
#include <set>
#include <unordered_set>
#include <vector>

using function_indext = int;
using instruction_indext = unsigned;
using valuet = uint64_t;

struct framet
{
  explicit framet(function_indext __function_index) : function_index(__function_index)
  {
  }

  // PC
  function_indext function_index;
  instruction_indext instruction_index = 0;

  // the "defers stack"
  using deferst = std::vector<function_indext>;
  deferst defers;

  // the function arguments
  std::vector<valuet> arguments;

  // any function-local data, in 64 bit units
  std::vector<valuet> local_data;

  bool panic_handler() const
  {
    return function_index == -1;
  }

  // could be 'default' in C++20
  bool operator==(const framet &other) const
  {
    return function_index == other.function_index &&
           instruction_index == other.instruction_index &&
           defers == other.defers &&
           arguments == other.arguments &&
           local_data == other.local_data;
  }
};

struct statet
{
  std::vector<framet> frames;

  framet &frame() { return frames.back(); }
  bool exited() const { return frames.empty(); }

  // could be 'default' in C++20
  bool operator==(const statet &other) const
  {
    return frames == other.frames;
  }

  void next_PC() { frame().instruction_index++; }
  void handle_panic();
  void nondet_Panic();

  void do_Call(function_indext);
  void do_DebugRef();
  void do_Defer(function_indext);
  void do_Go(function_indext);
  void do_If(instruction_indext, instruction_indext);
  void do_Jump(instruction_indext);
  void do_MapUpdate();
  void do_Panic();
  void do_Recover();
  void do_Return();
  void do_RunDefers();
  void do_Skip();
  void do_Send();
  void do_Store();
};

// Based on MurmurHash3, originally implemented by Austin Appleby who
// placed the code in the public domain, disclaiming any copyright.
// See the original source for details and further comments:
// https://code.google.com/p/smhasher/source/browse/trunk/MurmurHash3.cpp

static inline uint32_t ROTL32(uint32_t x, int8_t r)
{
  return (x << r) | (x >> (32-r));
}

static inline std::size_t murmurhash3_hash_combine(
  std::size_t h1,
  std::size_t h2)
{
  const uint32_t c1 = 0xcc9e2d51;
  const uint32_t c2 = 0x1b873593;

  h2 *= c1;
  h2 = ROTL32(h2, 15);
  h2 *= c2;

  h1 ^= h2;
  h1 = ROTL32(h1, 13);
  h1 = h1*5 + 0xe6546b64;

  return h1;
}

template<>
struct std::hash<framet>
{
  std::size_t operator()(const framet &frame) const noexcept
  {
    std::size_t result = 0;
    result = murmurhash3_hash_combine(result, frame.function_index);
    result = murmurhash3_hash_combine(result, frame.instruction_index);
    for(auto f : frame.defers)
      result = murmurhash3_hash_combine(result, f);
    for(auto data : frame.arguments)
    {
      result = murmurhash3_hash_combine(result, data);
      result = murmurhash3_hash_combine(result, data >> 32);
    }
    for(auto data : frame.local_data)
    {
      result = murmurhash3_hash_combine(result, data);
      result = murmurhash3_hash_combine(result, data >> 32);
    }
    return result;
  }
};

template<>
struct std::hash<std::vector<framet>>
{
  std::size_t operator()(const std::vector<framet> &frames) const noexcept
  {
    std::size_t result = 0;
    for(const framet &frame : frames)
      result = murmurhash3_hash_combine(result, std::hash<framet>{}(frame));
    return result;
  }
};

template<>
struct std::hash<statet>
{
  std::size_t operator()(const statet &state) const noexcept
  {
    return std::hash<std::vector<framet>>{}(state.frames);
  }
};

using state_sett = std::unordered_set<statet>;
state_sett seen;
state_sett error_states;

// We need the references to states to be stable
// when adding to the end of the queue.
using queuet = std::deque<statet>;
queuet queue;

void statet::do_Call(function_indext function_index)
{
  // push a new frame onto the call stack
  frames.emplace_back(function_index);
}

void statet::do_DebugRef()
{
  // DebugRef has no dynamic effect
  next_PC();
}

void statet::do_Defer(function_indext function_index)
{
  // add the given function to the defers stack
  frame().defers.push_back(function_index);
  next_PC();
}

void statet::do_Go(function_indext function_index)
{
  // create a new call stack
  statet new_thread;
  new_thread.frames.emplace_back(function_index);
  queue.push_back(std::move(new_thread));
  next_PC();
}

void statet::do_If(instruction_indext then_case, instruction_indext else_case)
{
  // duplicate the state to make the 'else case'
  queue.push_back(*this);
  queue.back().frame().instruction_index = else_case;

  frame().instruction_index = then_case;
}

void statet::do_Jump(instruction_indext target)
{
  frame().instruction_index = target;
}

void statet::do_MapUpdate()
{
  next_PC();
}

void statet::do_Panic()
{
  // While handling a panic, the stack leading to the panic
  // is preserved, and a function 'panic' is added to the stack.
  // -1 is the function index of the panic handler.
  // It has two units of 'local data'.
  frames.emplace_back(-1);
  frame().local_data.resize(2);
}

void statet::handle_panic()
{
  // We have two local variables:
  // local_data[0]: the frame that we are unravelling, where 0 is the topmost frame.
  // local_data[1]: true when recovered.

  if(frame().local_data[0] >= frames.size())
  {
    // No 'defers' are left, and we got to the bottom of the call stack without recover.
    // It's an error.
    error_states.insert(*this);
    frames.clear();
  }
  else
  {
    const std::size_t frame_index = frames.size() - frame().local_data[0] - 1;

    // Any 'defers' left to run for this frame?
    if(frames[frame_index].defers.empty()) // No.
    {
      // Did we recover?
      if(frame().local_data[1] != 0)
      {
        // Yes! We exit the panic handler, and continue with
        // the caller of the last function we have unravelled.
        // The result might be a no-panic exit state.
        frames.erase(frames.begin()+frame_index, frames.end());
      }
      else
      {
        // No, we did not recover. Go to the next frame.
        frame().local_data[0]++;
      }
    }
    else
    {
      // Call the 'defer' from the frame we are unravelling.
      auto defer_function_index = frames[frame_index].defers.back();
      frames[frame_index].defers.pop_back();
      frames.emplace_back(defer_function_index);
    }
  }
}

void statet::do_Recover()
{
  // Stop the panic:
  // look for the most recent frame with a panic handler.

  auto result = std::find_if(
    frames.rbegin(), frames.rend(),
    [](const framet &f) { return f.panic_handler(); });

  if(result == frames.rend())
  {
    // we are not panicking
  }
  else
  {
    // panic found -- stop it
    result->local_data[1] = true;
  }

  next_PC();
}

void statet::do_Return()
{
  // pop the frame off the call stack
  frames.pop_back();

  // increase the instruction index of the caller
  // unless this was the last frame
  if(!exited())
    next_PC();
}

void statet::do_RunDefers()
{
  // pops and invokes the entire stack of procedure calls
  // pushed by Defer instructions in this function

  if(frame().defers.empty())
    next_PC();
  else
  {
    auto defer_function_index = frame().defers.back();
    frame().defers.pop_back();
    frames.emplace_back(defer_function_index);
  }
}

void statet::do_Send()
{
  nondet_Panic();
  next_PC();
}

void statet::do_Skip()
{
  next_PC();
}

void statet::do_Store()
{
  //nondet_Panic();
  next_PC();
}

void statet::nondet_Panic()
{
  // for now, discard nested panics
  auto result = std::find_if(
    frames.rbegin(), frames.rend(),
    [](const framet &f) { return f.panic_handler(); });

  if(result != frames.rend())
  {
  }
  else
  {
    // make a copy of the state and panic there
    queue.push_back(*this);
    queue.back().do_Panic();
  }
}

//<--- INSERT CODE HERE --->

void search()
{
  queue = initial_states();

  while(!queue.empty())
  {
    auto &state = queue.back();

    auto seen_result = seen.insert(state);
    if(seen_result.second) // actually inserted
    {
      if(state.exited())
        queue.pop_back(); // no successor
      else
        trans(state); // compute successors
    }
    else
      queue.pop_back(); // drop the state
  }
}

int main()
{
  // find the reachable states
  std::cout << "Starting search\n";
  search();

  std::cout << "Found " << seen.size() << " reachable state(s)\n";

  // any errors?
  std::set<function_indext> errored_functions;

  for(const auto &error_state : error_states)
    if(!error_state.frames.empty())
    {
      auto error_function = error_state.frames.front().function_index;
      errored_functions.insert(error_function);
      
      std::cout << "unrecovered panic in "
                << function_names[error_function]
                << '\n';

      // use reverse ordering -- the top frame goes first
      for(auto f_it = error_state.frames.rbegin();
          f_it != error_state.frames.rend();
          f_it++)
      {
        const auto &frame = *f_it;
        std::cout << "  ";
        if(frame.panic_handler())
          std::cout << "panic";
        else
        {
          std::cout << function_names[frame.function_index];
          auto line = line_numbers[frame.function_index][frame.instruction_index];
          if(line != 0)
          {
            std::cout << ' ' << function_file_names[frame.function_index] << ':' << line;
          }
        }
        std::cout << '\n';
      }
    }

  if(errored_functions.empty())
  {
    std::cout << "no unrecovered panics found\n";
  }
}
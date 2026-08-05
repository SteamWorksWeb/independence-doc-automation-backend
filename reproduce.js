const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

async function run() {
  try {
    // 1. Create a dummy lawyer
    const lawyer = await prisma.lawyer.create({
      data: {
        name: 'Test Lawyer',
        email: 'lawyer' + Date.now() + '@test.com',
        passwordHash: 'hash',
        role: 'LAWYER'
      }
    });

    // 2. Create a dummy client
    const client = await prisma.client.create({
      data: {
        name: 'Unknown Client',
        email: 'client' + Date.now() + '@test.com',
        passwordHash: 'hash',
        isVerified: true,
        status: 'Pre-Filing',
        lawyerId: lawyer.id
      }
    });

    const clientId = client.id;
    const data = {
      phone: "888-888-8888",
      dob: "01/01/1978",
      ssn: "555-55-5555",
      householdSize: 1
    };

    // 3. Upsert intake profile
    console.log("Upserting intake profile...");
    const intakeProfile = await prisma.intakeProfile.upsert({
      where:  { clientId },
      create: { clientId, ...data },
      update: data,
    });
    console.log("Upsert successful:", intakeProfile.id);

    // 4. Update client phone
    console.log("Updating client phone...");
    await prisma.client.update({
      where: { id: clientId },
      data:  { phone: data.phone },
    });
    console.log("Update successful");

  } catch (e) {
    console.error("Error:", e);
  } finally {
    await prisma.$disconnect();
  }
}

run();
